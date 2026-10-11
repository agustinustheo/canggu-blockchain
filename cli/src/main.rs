//! `canggu`: a small wallet for the Canggu chain.
//!
//! Every transaction it sends is signed with ML-DSA-65 (FIPS 204). Dev keys are derived from
//! phrases such as `//Alice`; accounts can also be given in SS58 form wherever no signature is
//! needed.

mod chain;
mod rpc;

use anyhow::{bail, ensure, Context, Result};
use canggu_primitives::{
	keyring::{self, MlDsa65Pair},
	ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use canggu_runtime::{AccountId, Balance, BalancesCall, Runtime, RuntimeCall, RuntimeEvent};
use canggu_zk::PayrollCircuit;
use chain::{format_units, parse_units, Chain, Included};
use clap::{Parser, Subcommand};
use codec::{Decode, Encode};
use sp_core::crypto::Ss58Codec;
use sp_runtime::{DispatchError, ModuleError};
use std::{path::PathBuf, time::Instant};

#[derive(Parser)]
#[command(name = "canggu", about = "Canggu wallet (ML-DSA-65 / CRYSTALS-Dilithium accounts)")]
struct Cli {
	/// Node JSON-RPC endpoint.
	#[arg(long, global = true, default_value = "http://127.0.0.1:9944")]
	url: String,
	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand)]
enum Command {
	/// Show the account and key sizes for a secret phrase such as `//Alice`.
	Account { phrase: String },
	/// Show the free balance of an account (`//Name` or SS58).
	Balance { who: String },
	/// Transfer CGU, optionally only after other transactions (DAG parents).
	Transfer {
		#[arg(long)]
		from: String,
		#[arg(long)]
		to: String,
		/// Amount in CGU, e.g. `1.5`.
		#[arg(long)]
		amount: String,
		/// Parent transaction as `ACCOUNT:NONCE` (repeatable). The transfer is only executed
		/// after every parent.
		#[arg(long = "after")]
		after: Vec<String>,
		/// Tip in plancks (rejected by Canggu unless 0; useful to see the error).
		#[arg(long, default_value_t = 0)]
		tip: Balance,
	},
	/// Pay many accounts with a single debit: `--pay //Bob=10 --pay //Charlie=20`.
	Payroll {
		#[arg(long)]
		from: String,
		#[arg(long = "pay", required = true)]
		payments: Vec<String>,
	},
	/// Groth16 trusted setup (single party, demo only) for an N-recipient payroll circuit.
	ZkSetup {
		#[arg(long, default_value_t = 4)]
		recipients: usize,
		#[arg(long, default_value = "zk-keys")]
		out: PathBuf,
	},
	/// Register a verifying key on-chain.
	ZkRegister {
		#[arg(long)]
		from: String,
		#[arg(long, default_value = "zk-keys/vk.bin")]
		vk: PathBuf,
	},
	/// Prove that private salaries sum to their public total and match a commitment.
	ZkProve {
		#[arg(long, default_value = "zk-keys/pk.bin")]
		pk: PathBuf,
		#[arg(long)]
		salt: u64,
		/// Comma separated salaries (u64).
		#[arg(long, value_delimiter = ',')]
		amounts: Vec<u64>,
		#[arg(long, default_value = "proof.json")]
		out: PathBuf,
	},
	/// Submit a proof produced by `zk-prove` for on-chain verification.
	ZkSubmit {
		#[arg(long)]
		from: String,
		#[arg(long, default_value = "zk-keys/vk.bin")]
		vk: PathBuf,
		#[arg(long, default_value = "proof.json")]
		proof: PathBuf,
	},
	/// Run an end-to-end tour of every Canggu feature against a `--dev` node.
	Demo,
	/// Measure the native cryptography (no node needed).
	Bench {
		/// Payroll sizes to benchmark the zk circuit with.
		#[arg(long, value_delimiter = ',', default_value = "4,16,64,256")]
		recipients: Vec<usize>,
	},
}

fn main() -> Result<()> {
	let cli = Cli::parse();
	match cli.command {
		Command::Account { phrase } => {
			let pair = pair(&phrase)?;
			println!("account:     {}", pair.account_id());
			println!("scheme:      ML-DSA-65 (FIPS 204, CRYSTALS-Dilithium3, NIST level 3)");
			println!("public key:  {ML_DSA_65_PUBLIC_KEY_LEN} bytes");
			println!("signature:   {ML_DSA_65_SIGNATURE_LEN} bytes");
			Ok(())
		},
		Command::Balance { who } => {
			let chain = Chain::connect(&cli.url)?;
			let who = account(&who)?;
			println!("{who}: {}", format_units(chain.free_balance(&who)?));
			Ok(())
		},
		Command::Transfer { from, to, amount, after, tip } => {
			let chain = Chain::connect(&cli.url)?;
			let signer = pair(&from)?;
			let parents = after.iter().map(|p| parse_parent(p)).collect::<Result<Vec<_>>>()?;
			let call = transfer_call(&account(&to)?, parse_units(&amount)?);
			let nonce = chain.rpc.next_nonce(&signer.account_id())?;
			let xt = chain.sign(&signer, call, nonce, parents, tip)?;
			println!("sending {} bytes (nonce {nonce})...", xt.encoded_size());
			report(&chain.submit_and_wait(&xt)?)
		},
		Command::Payroll { from, payments } => {
			let chain = Chain::connect(&cli.url)?;
			let signer = pair(&from)?;
			let payments = payments
				.iter()
				.map(|p| {
					let (who, amount) = p.split_once('=').context("expected WHO=AMOUNT")?;
					Ok((account(who)?, parse_units(amount)?))
				})
				.collect::<Result<Vec<_>>>()?;
			let nonce = chain.rpc.next_nonce(&signer.account_id())?;
			let xt = chain.sign(&signer, payroll_call(payments)?, nonce, vec![], 0)?;
			report(&chain.submit_and_wait(&xt)?)
		},
		Command::ZkSetup { recipients, out } => {
			let started = Instant::now();
			let (pk, vk) = canggu_zk::setup(recipients, &mut rand::rngs::OsRng)?;
			std::fs::create_dir_all(&out)?;
			std::fs::write(out.join("pk.bin"), canggu_zk::encode(&pk))?;
			std::fs::write(out.join("vk.bin"), canggu_zk::encode(&vk))?;
			println!("setup for {recipients} recipients in {:?}", started.elapsed());
			println!("WARNING: single-party setup; the OS RNG output was the toxic waste.");
			Ok(())
		},
		Command::ZkRegister { from, vk } => {
			let chain = Chain::connect(&cli.url)?;
			let signer = pair(&from)?;
			let vk = std::fs::read(&vk)?;
			let call = register_vk_call(vk)?;
			let nonce = chain.rpc.next_nonce(&signer.account_id())?;
			report(&chain.submit_and_wait(&chain.sign(&signer, call, nonce, vec![], 0)?)?)
		},
		Command::ZkProve { pk, salt, amounts, out } => {
			let pk = canggu_zk::decode(&std::fs::read(&pk)?).context("bad proving key")?;
			let circuit = PayrollCircuit { salt: salt.into(), amounts };
			let inputs = circuit.public_inputs();
			let started = Instant::now();
			let proof = canggu_zk::prove(&pk, circuit, &mut rand::rngs::OsRng)?;
			println!("proved in {:?}", started.elapsed());
			let json = serde_json::json!({
				"public_inputs": inputs.iter().map(|x| hex::encode(canggu_zk::scalar_bytes(x))).collect::<Vec<_>>(),
				"proof": hex::encode(canggu_zk::encode(&proof)),
			});
			std::fs::write(&out, serde_json::to_string_pretty(&json)?)?;
			println!("wrote {}", out.display());
			Ok(())
		},
		Command::ZkSubmit { from, vk, proof } => {
			let chain = Chain::connect(&cli.url)?;
			let signer = pair(&from)?;
			let vk = std::fs::read(&vk)?;
			let json: serde_json::Value = serde_json::from_slice(&std::fs::read(&proof)?)?;
			let inputs = json["public_inputs"]
				.as_array()
				.context("public_inputs")?
				.iter()
				.map(|x| {
					let bytes = hex::decode(x.as_str().context("hex")?)?;
					<[u8; 32]>::try_from(bytes)
						.map_err(|_| anyhow::anyhow!("input is not 32 bytes"))
				})
				.collect::<Result<Vec<_>>>()?;
			let proof = hex::decode(json["proof"].as_str().context("proof")?)?;
			let call = submit_proof_call(&vk, inputs, proof)?;
			let nonce = chain.rpc.next_nonce(&signer.account_id())?;
			report(&chain.submit_and_wait(&chain.sign(&signer, call, nonce, vec![], 0)?)?)
		},
		Command::Demo => demo(&Chain::connect(&cli.url)?),
		Command::Bench { recipients } => bench(&recipients),
	}
}

/// A signing key from a dev phrase (`//Alice`). Real deployments would use a proper keystore.
fn pair(phrase: &str) -> Result<MlDsa65Pair> {
	ensure!(phrase.starts_with("//"), "signing keys are given as phrases such as //Alice");
	Ok(MlDsa65Pair::from_phrase(phrase))
}

fn account(who: &str) -> Result<AccountId> {
	if who.starts_with("//") {
		return Ok(MlDsa65Pair::from_phrase(who).account_id());
	}
	AccountId::from_ss58check(who).map_err(|e| anyhow::anyhow!("bad account {who}: {e:?}"))
}

fn parse_parent(parent: &str) -> Result<(AccountId, u32)> {
	let (who, nonce) = parent.rsplit_once(':').context("expected ACCOUNT:NONCE")?;
	Ok((account(who)?, nonce.parse()?))
}

fn transfer_call(to: &AccountId, value: Balance) -> RuntimeCall {
	RuntimeCall::Balances(BalancesCall::transfer_keep_alive { dest: to.clone().into(), value })
}

fn payroll_call(payments: Vec<(AccountId, Balance)>) -> Result<RuntimeCall> {
	let payments = payments.try_into().map_err(|_| anyhow::anyhow!("too many recipients"))?;
	Ok(RuntimeCall::Payroll(pallet_parallel_payroll::Call::batch_pay { payments }))
}

fn register_vk_call(vk: Vec<u8>) -> Result<RuntimeCall> {
	let vk = vk.try_into().map_err(|_| anyhow::anyhow!("verifying key too large"))?;
	Ok(RuntimeCall::ZkVerifier(pallet_zk_verifier::Call::register_verifying_key { vk }))
}

fn submit_proof_call(vk: &[u8], inputs: Vec<[u8; 32]>, proof: Vec<u8>) -> Result<RuntimeCall> {
	use sp_runtime::traits::{BlakeTwo256, Hash};
	Ok(RuntimeCall::ZkVerifier(pallet_zk_verifier::Call::submit_proof {
		vk: BlakeTwo256::hash(vk),
		public_inputs: inputs.try_into().map_err(|_| anyhow::anyhow!("too many inputs"))?,
		proof: proof.try_into().map_err(|_| anyhow::anyhow!("proof too large"))?,
	}))
}

pub fn describe_dispatch_error(error: &DispatchError) -> String {
	let DispatchError::Module(ModuleError { index, error, .. }) = error else {
		return format!("{error:?}");
	};
	let bytes = &mut &error[..];
	match index {
		7 => pallet_zk_verifier::Error::<Runtime>::decode(bytes)
			.map(|e| format!("ZkVerifier::{e:?}")),
		8 => pallet_parallel_payroll::Error::<Runtime>::decode(bytes)
			.map(|e| format!("Payroll::{e:?}")),
		_ => Ok(format!("module {index} error {error:?}")),
	}
	.unwrap_or_else(|_| format!("module {index} error {error:?}"))
}

fn report(included: &Included) -> Result<()> {
	println!("included in block #{} at index {}", included.block_number, included.index);
	for event in &included.events {
		println!("  event: {}", short_event(event));
	}
	if let Some(failure) = included.failure() {
		bail!("dispatch failed: {failure}");
	}
	Ok(())
}

fn short_event(event: &RuntimeEvent) -> String {
	let text = format!("{event:?}");
	if text.len() > 160 {
		format!("{}...", &text[..157])
	} else {
		text
	}
}

fn step(title: &str) {
	println!("\n=== {title} ===");
}

fn demo(chain: &Chain) -> Result<()> {
	let [alice, bob, charlie, dave, eve] = keyring::DEV_NAMES.map(keyring::dev);

	step("1. Post-quantum accounts (ML-DSA-65 / CRYSTALS-Dilithium3)");
	for (name, pair) in keyring::DEV_NAMES.iter().zip([&alice, &bob, &charlie, &dave, &eve]) {
		println!(
			"  {name:<8} {}  {}",
			pair.account_id(),
			format_units(chain.free_balance(&pair.account_id())?)
		);
	}
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	let xt = chain.sign(
		&alice,
		transfer_call(&dave.account_id(), 100 * chain::UNIT),
		nonce,
		vec![],
		0,
	)?;
	println!(
		"  Alice -> Dave 100 CGU: {} byte extrinsic ({}-byte key + {}-byte signature inside)",
		xt.encoded_size(),
		ML_DSA_65_PUBLIC_KEY_LEN,
		ML_DSA_65_SIGNATURE_LEN
	);
	report(&chain.submit_and_wait(&xt)?)?;

	step("2. DAG-ordered transactions (cross-account dependencies)");
	let bob_nonce = chain.rpc.next_nonce(&bob.account_id())?;
	let charlie_nonce = chain.rpc.next_nonce(&charlie.account_id())?;
	let parent = chain.sign(
		&bob,
		transfer_call(&eve.account_id(), 10 * chain::UNIT),
		bob_nonce,
		vec![],
		0,
	)?;
	let child = chain.sign(
		&charlie,
		transfer_call(&eve.account_id(), 20 * chain::UNIT),
		charlie_nonce,
		vec![(bob.account_id(), bob_nonce)],
		0,
	)?;
	println!("  submitting Charlie's tx FIRST; it declares Bob's tx (nonce {bob_nonce}) as parent");
	let child_pending = chain.submit(&child)?;
	let start = chain.rpc.best_number()?;
	while chain.rpc.best_number()? < start + 2 {
		std::thread::sleep(std::time::Duration::from_millis(250));
	}
	let now = chain.rpc.best_number()?;
	ensure!(
		chain.included_by(&child_pending, now)?.is_none(),
		"the child was included before its parent existed"
	);
	println!(
		"  {} blocks later the child is still not in any block: it waits for its parent",
		now - start
	);
	println!("  now submitting Bob's parent tx");
	let parent_included = chain.submit_and_wait(&parent)?;
	let child_included = chain.wait(&child_pending)?;
	println!(
		"  parent: block #{} index {} | child: block #{} index {}",
		parent_included.block_number,
		parent_included.index,
		child_included.block_number,
		child_included.index
	);
	ensure!(
		(parent_included.block_number, parent_included.index) <
			(child_included.block_number, child_included.index),
		"child executed before parent!"
	);
	println!("  ok: the child executed strictly after its parent");

	step("3. No priority auction: tips are rejected");
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	let tipped =
		chain.sign(&alice, transfer_call(&bob.account_id(), chain::UNIT), nonce, vec![], 1_000)?;
	match chain.submit(&tipped) {
		Ok(_) => bail!("a tipped transaction was accepted"),
		Err(e) => println!("  rejected by the pool as expected: {e}"),
	}

	step("4. Payroll: one debit, conflict-free parallel credits");
	let payments = vec![
		(bob.account_id(), 1_000 * chain::UNIT),
		(charlie.account_id(), 2_000 * chain::UNIT),
		(dave.account_id(), 1_500 * chain::UNIT),
		(eve.account_id(), 2_500 * chain::UNIT),
	];
	let before: Vec<Balance> =
		payments.iter().map(|(who, _)| chain.free_balance(who)).collect::<Result<_>>()?;
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	report(&chain.submit_and_wait(&chain.sign(
		&alice,
		payroll_call(payments.clone())?,
		nonce,
		vec![],
		0,
	)?)?)?;
	for ((who, amount), before) in payments.iter().zip(before) {
		let after = chain.free_balance(who)?;
		ensure!(after == before + amount, "{who} was not paid correctly");
		println!("  {who}: +{}", format_units(after - before));
	}
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	let duplicate =
		payroll_call(vec![(bob.account_id(), chain::UNIT), (bob.account_id(), chain::UNIT)])?;
	let included = chain.submit_and_wait(&chain.sign(&alice, duplicate, nonce, vec![], 0)?)?;
	let failure = included.failure().context("a conflicting payroll batch was accepted")?;
	println!("  batch paying Bob twice: rejected with {failure}");

	step("5. zk-SNARK: prove a private payroll off-chain, verify on-chain");
	let salaries = vec![1_000u64, 2_000, 1_500, 2_500];
	let started = Instant::now();
	let (pk, vk) = canggu_zk::setup(salaries.len(), &mut rand::rngs::OsRng)?;
	println!("  trusted setup (demo, single party): {:?}", started.elapsed());
	let circuit = PayrollCircuit { salt: 0xC0FFEE_u64.into(), amounts: salaries };
	let [total, commitment] = circuit.public_inputs();
	let started = Instant::now();
	let proof = canggu_zk::encode(&canggu_zk::prove(&pk, circuit, &mut rand::rngs::OsRng)?);
	println!("  proof generated on CPU in {:?}: {} bytes", started.elapsed(), proof.len());
	let vk = canggu_zk::encode(&vk);
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	report(&chain.submit_and_wait(&chain.sign(
		&alice,
		register_vk_call(vk.clone())?,
		nonce,
		vec![],
		0,
	)?)?)?;

	let inputs = vec![canggu_zk::scalar_bytes(&total), canggu_zk::scalar_bytes(&commitment)];
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	let call = submit_proof_call(&vk, inputs, proof.clone())?;
	report(&chain.submit_and_wait(&chain.sign(&alice, call, nonce, vec![], 0)?)?)?;
	println!("  ok: the chain verified the payroll total without seeing any salary");

	let forged = vec![
		canggu_zk::scalar_bytes(&(total + canggu_zk::Scalar::from(1u64))),
		canggu_zk::scalar_bytes(&commitment),
	];
	let nonce = chain.rpc.next_nonce(&alice.account_id())?;
	let call = submit_proof_call(&vk, forged, proof)?;
	let included = chain.submit_and_wait(&chain.sign(&alice, call, nonce, vec![], 0)?)?;
	let failure = included.failure().context("a proof for a forged total was accepted")?;
	println!("  same proof, claimed total + 1: rejected with {failure}");

	println!("\nAll Canggu features exercised successfully.");
	Ok(())
}

fn time<T>(iterations: u32, mut f: impl FnMut() -> T) -> std::time::Duration {
	let started = Instant::now();
	for _ in 0..iterations {
		std::hint::black_box(f());
	}
	started.elapsed() / iterations
}

fn bench(recipients: &[usize]) -> Result<()> {
	let alice = keyring::dev("Alice");
	let msg = [7u8; 256];
	let signature = alice.sign_raw(&msg);
	let public = alice.public();
	println!("ML-DSA-65 (pure Rust, 1 core)");
	println!("  sign    {:>10.1?}", time(200, || alice.sign_raw(&msg)));
	println!("  verify  {:>10.1?}", time(200, || keyring::verify(&public.0, &msg, &signature.0)));
	println!(
		"  sizes   public key {ML_DSA_65_PUBLIC_KEY_LEN} B, signature {ML_DSA_65_SIGNATURE_LEN} B"
	);

	println!("Groth16 / BLS12-381 payroll circuit (arkworks, all cores for proving)");
	println!(
		"  {:>10} {:>12} {:>12} {:>12} {:>12} {:>8}",
		"recipients", "constraints", "setup", "prove", "verify", "proof"
	);
	for &n in recipients {
		let cs = canggu_zk::constraint_count(n)?;
		let started = Instant::now();
		let (pk, vk) = canggu_zk::setup(n, &mut rand::rngs::OsRng)?;
		let setup = started.elapsed();
		let circuit = PayrollCircuit { salt: 1u64.into(), amounts: (1..=n as u64).collect() };
		let inputs: Vec<u8> =
			circuit.public_inputs().iter().flat_map(canggu_zk::scalar_bytes).collect();
		let started = Instant::now();
		let proof = canggu_zk::encode(&canggu_zk::prove(&pk, circuit, &mut rand::rngs::OsRng)?);
		let prove = started.elapsed();
		let vk = canggu_zk::encode(&vk);
		ensure!(canggu_primitives::zk::verify(&vk, &inputs, &proof), "proof does not verify");
		let verify = time(20, || canggu_primitives::zk::verify(&vk, &inputs, &proof));
		println!(
			"  {n:>10} {cs:>12} {:>12.1?} {:>12.1?} {:>12.1?} {:>6} B",
			setup,
			prove,
			verify,
			proof.len()
		);
	}
	Ok(())
}
