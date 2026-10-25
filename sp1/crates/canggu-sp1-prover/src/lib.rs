//! Host side of canggu-sp1: execute and prove the two SP1 guests on the CPU.
//!
//! * `mldsa-batch`: "every one of these `n` ML-DSA-65 signatures is valid"; public values
//!   `n | keccak256(ctx) | keccak256(concat(blake2_256(pk_i) | keccak256(msg_i)))`.
//! * `payroll`: "I know `salt`, `amounts` summing to `total` with commitment
//!   `keccak256(salt | amounts)`"; public values `n | total | commitment`.
//!
//! Proofs are SP1 *compressed* proofs: a single recursion STARK over KoalaBear (Poseidon2 Merkle
//! commitments, FRI/Basefold), i.e. hash-based and plausibly post-quantum. Nothing is wrapped into
//! Groth16/PLONK. Verify them with the `canggu-sp1-verify` crate (depends only on
//! `sp1-verifier`).
//!
//! The guest ELFs are committed under `elf/` and embedded here, so this crate does not need the
//! SP1 toolchain to build; `scripts/build-elfs.sh` rebuilds them.

use anyhow::{bail, ensure, Context, Result};
use sp1_sdk::{
	blocking::{CpuProver, ProveRequest, Prover},
	Elf, HashableKey, ProvingKey, SP1Proof, SP1ProvingKey, SP1Stdin,
};
use std::sync::OnceLock;

pub mod testkit;

pub use canggu_mldsa::{batch::PUBLIC_VALUES_BYTES as MLDSA_PUBLIC_VALUES_BYTES, blake2_256};
pub use canggu_mldsa::{keccak256, payroll::PUBLIC_VALUES_BYTES as PAYROLL_PUBLIC_VALUES_BYTES};

static MLDSA_BATCH_ELF: &[u8] = include_bytes!("../../../elf/mldsa-batch.elf");
static MLDSA_BATCH_SOFT_KECCAK_ELF: &[u8] =
	include_bytes!("../../../elf/mldsa-batch-soft-keccak.elf");
static PAYROLL_ELF: &[u8] = include_bytes!("../../../elf/payroll.elf");

/// The `mldsa-batch` guest ELF (Keccak through the SP1 precompile).
pub fn mldsa_batch_elf() -> &'static [u8] {
	MLDSA_BATCH_ELF
}

/// The `payroll` guest ELF.
pub fn payroll_elf() -> &'static [u8] {
	PAYROLL_ELF
}

/// The guest programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Program {
	/// `programs/mldsa-batch` with the Keccak precompile (the one to deploy).
	MldsaBatch,
	/// `programs/mldsa-batch` built without the Keccak precompile (benchmark comparison only).
	MldsaBatchSoftKeccak,
	/// `programs/payroll`.
	Payroll,
}

impl Program {
	/// The embedded ELF.
	pub fn elf(self) -> &'static [u8] {
		match self {
			Program::MldsaBatch => MLDSA_BATCH_ELF,
			Program::MldsaBatchSoftKeccak => MLDSA_BATCH_SOFT_KECCAK_ELF,
			Program::Payroll => PAYROLL_ELF,
		}
	}

	/// Short name (file names, logs).
	pub fn name(self) -> &'static str {
		match self {
			Program::MldsaBatch => "mldsa-batch",
			Program::MldsaBatchSoftKeccak => "mldsa-batch-soft-keccak",
			Program::Payroll => "payroll",
		}
	}

	/// The vkey hash committed in `canggu-sp1-verify` (what a chain would store), if any.
	pub fn committed_vkey_hash(self) -> Option<&'static [u8]> {
		match self {
			Program::MldsaBatch => Some(canggu_sp1_verify::MLDSA_BATCH_VKEY_HASH),
			Program::MldsaBatchSoftKeccak => None,
			Program::Payroll => Some(canggu_sp1_verify::PAYROLL_VKEY_HASH),
		}
	}

	fn index(self) -> usize {
		self as usize
	}
}

/// A compressed proof in the exact byte formats `canggu_sp1_verify::verify` takes.
#[derive(Clone, Debug)]
pub struct Proved {
	/// `bincode(SP1Proof::Compressed(..))`.
	pub proof: Vec<u8>,
	/// The raw bytes committed by the guest.
	pub public_values: Vec<u8>,
	/// `bincode(vk.hash_koalabear())` (32 bytes).
	pub vkey_hash: Vec<u8>,
	/// RISC-V instructions executed (from a separate execution, for reporting).
	pub cycles: u64,
}

/// The result of executing a guest without proving.
#[derive(Clone, Debug)]
pub struct Executed {
	/// The raw bytes committed by the guest.
	pub public_values: Vec<u8>,
	/// RISC-V instructions executed.
	pub cycles: u64,
	/// Number of `ecall`s (precompiles, I/O, ...).
	pub syscalls: u64,
	/// Number of Keccak-permute precompile calls.
	pub keccak_permutes: u64,
	/// SP1's "prover gas" estimate, if computed (a better predictor of proving cost than cycles
	/// because it accounts for precompile and memory costs).
	pub gas: Option<u64>,
}

/// The process-wide CPU prover. Building it is expensive (it sets up the recursion machinery), so
/// it is created once and shared.
pub fn client() -> &'static CpuProver {
	static CLIENT: OnceLock<CpuProver> = OnceLock::new();
	CLIENT.get_or_init(CpuProver::new)
}

/// The proving key of `program` (cached; `setup` costs a few seconds).
pub fn proving_key(program: Program) -> Result<&'static SP1ProvingKey> {
	static KEYS: [OnceLock<SP1ProvingKey>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
	let slot = &KEYS[program.index()];
	if let Some(pk) = slot.get() {
		return Ok(pk);
	}
	let pk = client()
		.setup(Elf::Static(program.elf()))
		.map_err(|e| anyhow::anyhow!("setup of {} failed: {e}", program.name()))?;
	Ok(slot.get_or_init(|| pk))
}

/// `bincode(vk.hash_koalabear())` for `program`, as computed by `setup` from the embedded ELF.
pub fn vkey_hash(program: Program) -> Result<Vec<u8>> {
	let pk = proving_key(program)?;
	Ok(bincode::serialize(&pk.verifying_key().hash_koalabear())?)
}

fn stdin_with(input: Vec<u8>) -> SP1Stdin {
	let mut stdin = SP1Stdin::new();
	stdin.write_vec(input);
	stdin
}

/// Execute `program` on the raw guest input `input` (see `canggu_mldsa::{batch, payroll}`).
/// Fails if the guest panics (e.g. an invalid signature) or exits with a non-zero code.
pub fn execute(program: Program, input: Vec<u8>) -> Result<Executed> {
	let (pv, report) = client()
		.execute(Elf::Static(program.elf()), stdin_with(input))
		.calculate_gas(true)
		.run()
		.map_err(|e| anyhow::anyhow!("execution of {} failed: {e}", program.name()))?;
	ensure!(report.exit_code == 0, "{} exited with code {}", program.name(), report.exit_code);
	let keccak_permutes = report
		.syscall_counts
		.iter()
		.filter(|(code, _)| format!("{code:?}") == "KECCAK_PERMUTE")
		.map(|(_, n)| *n)
		.sum();
	Ok(Executed {
		public_values: pv.to_vec(),
		cycles: report.total_instruction_count(),
		syscalls: report.total_syscall_count(),
		keccak_permutes,
		gas: report.gas(),
	})
}

/// Produce a compressed proof of `program` on `input`.
///
/// Executes first (cheap) so that invalid inputs fail fast with a clear error instead of deep
/// inside the prover, and so the cycle count can be reported.
pub fn prove(program: Program, input: Vec<u8>) -> Result<Proved> {
	let executed = execute(program, input.clone())?;
	let pk = proving_key(program)?;
	let proof = client()
		.prove(pk, stdin_with(input))
		.compressed()
		.run()
		.map_err(|e| anyhow::anyhow!("proving {} failed: {e}", program.name()))?;
	ensure!(
		proof.public_values.as_slice() == executed.public_values.as_slice(),
		"prover and executor disagree on the public values"
	);
	if !matches!(proof.proof, SP1Proof::Compressed(_)) {
		bail!("expected a compressed proof, got {}", proof.proof);
	}
	let vkey_hash = bincode::serialize(&pk.verifying_key().hash_koalabear())?;
	// A chain verifies against the committed hash; a stale ELF would yield useless proofs.
	if let Some(committed) = program.committed_vkey_hash() {
		ensure!(
			vkey_hash == committed,
			"{}: vkey hash differs from canggu-sp1-verify's (run `bench vkeys`)",
			program.name()
		);
	}
	Ok(Proved {
		proof: bincode::serialize(&proof.proof).context("serializing proof")?,
		public_values: proof.public_values.to_vec(),
		vkey_hash,
		cycles: executed.cycles,
	})
}

/// Prove that every `(public_key, message, signature)` in `items` is a valid ML-DSA-65 signature
/// under context string `ctx`. Fails (no proof exists) if any signature is invalid.
pub fn prove_mldsa_batch(ctx: &[u8], items: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Result<Proved> {
	prove(Program::MldsaBatch, canggu_mldsa::batch::encode_input(ctx, items))
}

/// Execute (no proof) the `mldsa-batch` guest.
pub fn execute_mldsa_batch(ctx: &[u8], items: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Result<Executed> {
	execute(Program::MldsaBatch, canggu_mldsa::batch::encode_input(ctx, items))
}

/// Prove the payroll statement for `(salt, amounts)`.
pub fn prove_payroll(salt: [u8; 32], amounts: &[u64]) -> Result<Proved> {
	prove(Program::Payroll, canggu_mldsa::payroll::encode_input(&salt, amounts))
}

/// Execute (no proof) the `payroll` guest.
pub fn execute_payroll(salt: [u8; 32], amounts: &[u64]) -> Result<Executed> {
	execute(Program::Payroll, canggu_mldsa::payroll::encode_input(&salt, amounts))
}

/// The `mldsa-batch` public values a runtime recomputes from the context string, each signer's
/// `AccountId = blake2_256(public_key)` and each message (same order as the proven batch).
pub fn expected_public_values_mldsa(
	ctx: &[u8],
	accounts: &[[u8; 32]],
	msgs: &[Vec<u8>],
) -> Vec<u8> {
	canggu_mldsa::batch::expected_public_values(ctx, accounts, msgs).to_vec()
}

/// The `payroll` public values: `n: u32 LE | total: u128 LE | commitment`.
pub fn expected_public_values_payroll(n: u32, total: u128, commitment: &[u8; 32]) -> Vec<u8> {
	let mut out = Vec::with_capacity(PAYROLL_PUBLIC_VALUES_BYTES);
	out.extend_from_slice(&n.to_le_bytes());
	out.extend_from_slice(&total.to_le_bytes());
	out.extend_from_slice(commitment);
	out
}
