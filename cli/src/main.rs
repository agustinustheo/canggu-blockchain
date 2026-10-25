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
	/// Sign `count` transfer intents with fresh ML-DSA keys and submit them as one batch. The
	/// runtime verifies all signatures in a single host call (see the node's `⚡` log line).
	Intents {
		/// Relayer that submits the batch and pays its fee.
		#[arg(long, default_value = "//Alice")]
		relayer: String,
		#[arg(long, default_value_t = 256)]
		count: usize,
		/// Number of distinct signing accounts (funded automatically).
		#[arg(long, default_value_t = 64)]
		senders: usize,
		/// Tamper with this many intents after signing; they must be rejected.
		#[arg(long, default_value_t = 0)]
		forge: usize,
		/// Signature compression: prove all signatures with SP1 (`canggu-sp1`, or the binary in
		/// `CANGGU_SP1_PROVER`) and submit only senders, intents and the proof.
		#[arg(long)]
		compressed: bool,
	},
	/// Post-quantum payroll proof: private salaries sum to a public total (SP1 STARK).
	ZkSp1 {
		#[arg(long)]
		from: String,
		/// Any string; hashed into the commitment's 32-byte salt.
		#[arg(long)]
		salt: String,
		#[arg(long, value_delimiter = ',')]
		amounts: Vec<u64>,
	},
	/// Sealed (order-then-reveal) ordering: a relayer commits hashes, senders reveal in reverse
	/// order, and the chain executes in a canonical order nobody chose.
	Sealed {
		#[arg(long, default_value = "//Alice")]
		relayer: String,
	},
	/// Measure finality latency: time from a block's first appearance to its finalization.
	Finality {
		#[arg(long, default_value_t = 60)]
		seconds: u64,
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
		Command::ZkSp1 { from, salt, amounts } => {
			zk_sp1(&Chain::connect(&cli.url)?, &pair(&from)?, &salt, &amounts)
		},
		Command::Intents { relayer, count, senders, forge, compressed } => {
			intents(&Chain::connect(&cli.url)?, &pair(&relayer)?, count, senders, forge, compressed)
				.map(|_| ())
		},
		Command::Sealed { relayer } => sealed(&Chain::connect(&cli.url)?, &pair(&relayer)?),
		Command::Finality { seconds } => finality(&rpc::Rpc::new(&cli.url), seconds),
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

	step("6. Post-quantum intents: one batch, one (GPU-accelerable) host call");
	let (executed, rejected) = intents(chain, &alice, 64, 16, 2, false)?;
	ensure!((executed, rejected) == (62, 2), "unexpected batch outcome");

	step("7. Sealed ordering: commit hashes, reveal later, canonical execution order");
	sealed(chain, &alice)?;

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

/// Sign and submit a batch of intents. Returns `(executed, rejected)`.
fn intents(
	chain: &Chain,
	relayer: &MlDsa65Pair,
	count: usize,
	senders: usize,
	forge: usize,
	compressed: bool,
) -> Result<(u32, u32)> {
	use pallet_pq_intents::{Intent, SignedIntent};
	use rayon::prelude::*;
	ensure!(senders > 0 && count > 0, "need at least one sender and one intent");
	ensure!(forge <= count.min(senders), "can forge at most min(count, senders) intents");

	let senders: Vec<MlDsa65Pair> = (0..senders)
		.map(|i| MlDsa65Pair::from_phrase(&format!("//intent-sender/{i}")))
		.collect();
	let unfunded: Vec<(AccountId, Balance)> = senders
		.iter()
		.map(|s| Ok((s.account_id(), chain.free_balance(&s.account_id())?)))
		.collect::<Result<Vec<_>>>()?
		.into_iter()
		.filter(|(_, balance)| *balance < chain::UNIT)
		.map(|(who, _)| (who, 10 * chain::UNIT))
		.collect();
	if !unfunded.is_empty() {
		println!("  funding {} sender accounts with one payroll batch", unfunded.len());
		let nonce = chain.rpc.next_nonce(&relayer.account_id())?;
		report_quiet(&chain.submit_and_wait(&chain.sign(
			relayer,
			payroll_call(unfunded)?,
			nonce,
			vec![],
			0,
		)?)?)?;
	}

	let mut next_nonce: Vec<u32> = senders
		.iter()
		.map(|s| {
			let key = pallet_pq_intents::Nonces::<Runtime>::hashed_key_for(s.account_id());
			Ok(chain.rpc.storage::<u32>(&key, None)?.unwrap_or_default())
		})
		.collect::<Result<_>>()?;
	let plan: Vec<(usize, Intent<AccountId, Balance>)> = (0..count)
		.map(|i| {
			let s = i % senders.len();
			let to = senders[(i + 1) % senders.len()].account_id();
			let nonce = next_nonce[s];
			next_nonce[s] += 1;
			(s, Intent { to, amount: chain::UNIT / 1_000, nonce })
		})
		.collect();

	let started = Instant::now();
	let genesis = chain.genesis;
	let mut batch: Vec<SignedIntent<AccountId, Balance>> = plan
		.into_par_iter()
		.map(|(s, intent)| SignedIntent {
			public: senders[s].public(),
			signature: senders[s].sign_raw(&pallet_pq_intents::signing_payload(&genesis, &intent)),
			intent,
		})
		.collect();
	println!(
		"  signed {count} intents with {} ML-DSA-65 keys in {:.2?}",
		senders.len(),
		started.elapsed()
	);
	// Tamper after signing. Forge the *last* intent of distinct senders so that no later intent of
	// the same sender is rejected for a nonce gap.
	for intent in batch.iter_mut().rev().take(forge) {
		intent.intent.amount += 1;
	}

	let signed_size = RuntimeCall::Intents(pallet_pq_intents::Call::submit_intents {
		intents: batch.clone().try_into().unwrap_or_default(),
	})
	.encoded_size();
	let call = if compressed {
		ensure!(forge == 0, "a batch with forged signatures cannot be proven");
		let items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = batch
			.iter()
			.map(|s| {
				let message = pallet_pq_intents::signing_payload(&genesis, &s.intent);
				(s.public.0.to_vec(), message, s.signature.0.to_vec())
			})
			.collect();
		let (proof, _) = run_sp1_prover("mldsa", &mldsa_batch_input(&items))?;
		let intents: Vec<(AccountId, Intent<AccountId, Balance>)> =
			batch.into_iter().map(|s| (s.public.to_account_id(), s.intent)).collect();
		RuntimeCall::Intents(pallet_pq_intents::Call::submit_compressed {
			intents: intents.try_into().map_err(|_| anyhow::anyhow!("too many intents"))?,
			proof: proof.try_into().map_err(|_| anyhow::anyhow!("proof too large"))?,
		})
	} else {
		RuntimeCall::Intents(pallet_pq_intents::Call::submit_intents {
			intents: batch
				.try_into()
				.map_err(|_| anyhow::anyhow!("too many intents for one batch"))?,
		})
	};
	let nonce = chain.rpc.next_nonce(&relayer.account_id())?;
	let xt = chain.sign(relayer, call, nonce, vec![], 0)?;
	if compressed {
		println!(
			"  relayer submits {:.2} MB (one SP1 proof, no keys or signatures) instead of {:.2} MB",
			xt.encoded_size() as f64 / 1e6,
			signed_size as f64 / 1e6
		);
	} else {
		println!(
			"  relayer submits one {:.2} MB extrinsic; the node's log shows which backend verified it",
			xt.encoded_size() as f64 / 1e6
		);
	}
	let included = chain.submit_and_wait(&xt)?;
	if let Some(failure) = included.failure() {
		bail!("batch failed: {failure}");
	}
	let mut reasons = std::collections::BTreeMap::<String, u32>::new();
	let mut outcome = None;
	for event in &included.events {
		match event {
			RuntimeEvent::Intents(pallet_pq_intents::Event::IntentRejected { reason, .. }) => {
				*reasons.entry(format!("{reason:?}")).or_default() += 1
			},
			RuntimeEvent::Intents(pallet_pq_intents::Event::BatchExecuted {
				executed,
				rejected,
				..
			}) => outcome = Some((*executed, *rejected)),
			_ => {},
		}
	}
	let (executed, rejected) = outcome.context("no BatchExecuted event")?;
	println!(
		"  block #{}: {executed} intents executed, {rejected} rejected {reasons:?}",
		included.block_number
	);
	Ok((executed, rejected))
}

fn report_quiet(included: &Included) -> Result<()> {
	match included.failure() {
		Some(failure) => bail!("dispatch failed: {failure}"),
		None => Ok(()),
	}
}

/// Order-then-reveal: commitments fix the order before anyone knows the contents.
fn sealed(chain: &Chain, relayer: &MlDsa65Pair) -> Result<()> {
	use frame_support::traits::Get;
	use pallet_sealed_ordering::{commitment_of, order_key, Event as Sealed};

	let names = ["Bob", "Charlie", "Dave", "Eve"];
	let senders = names.map(keyring::dev);
	let to = keyring::dev("Alice").account_id();
	struct Plan {
		name: &'static str,
		call: RuntimeCall,
		salt: [u8; 32],
		commitment: [u8; 32],
	}
	let plans: Vec<Plan> = names
		.iter()
		.zip(&senders)
		.enumerate()
		.map(|(i, (name, sender))| {
			let call = transfer_call(&to, (i as u128 + 1) * chain::UNIT);
			let salt: [u8; 32] = rand::random();
			let commitment = commitment_of(&sender.account_id(), &call.encode(), &salt);
			Plan { name, call, salt, commitment }
		})
		.collect();

	// 1. The relayer commits all four. On chain these are four 32-byte hashes from one account.
	let nonce = chain.rpc.next_nonce(&relayer.account_id())?;
	let pending = plans
		.iter()
		.enumerate()
		.map(|(k, plan)| {
			let call = RuntimeCall::Sealed(pallet_sealed_ordering::Call::commit {
				commitment: plan.commitment,
			});
			chain.submit(&chain.sign(relayer, call, nonce + k as u32, vec![], 0)?)
		})
		.collect::<Result<Vec<_>>>()?;
	let commit_blocks: Vec<u32> = pending
		.iter()
		.map(|p| chain.wait(p).map(|i| i.block_number))
		.collect::<Result<_>>()?;
	println!(
		"  relayer committed 4 opaque 32-byte hashes in block(s) {:?}: nobody can tell who pays whom",
		commit_blocks.iter().collect::<std::collections::BTreeSet<_>>()
	);

	// 2. Bob, Charlie and Dave reveal, in reverse order. Eve never reveals.
	let mut reveals = vec![];
	for k in (0..3).rev() {
		let (plan, sender) = (&plans[k], &senders[k]);
		let call = RuntimeCall::Sealed(pallet_sealed_ordering::Call::reveal {
			block: commit_blocks[k],
			call: Box::new(plan.call.clone()),
			salt: plan.salt,
		});
		let nonce = chain.rpc.next_nonce(&sender.account_id())?;
		reveals.push((plan.name, chain.submit(&chain.sign(sender, call, nonce, vec![], 0)?)?));
	}
	for (name, pending) in &reveals {
		let included = chain.wait(pending)?;
		if let Some(failure) = included.failure() {
			bail!("{name}'s reveal failed: {failure}");
		}
		println!(
			"  {name} revealed in block #{} (index {})",
			included.block_number, included.index
		);
	}

	// 3. Each commit block settles RevealWindow + 1 blocks later, in canonical order.
	let delay = <<Runtime as pallet_sealed_ordering::Config>::RevealWindow as Get<u32>>::get() + 1;
	let mut blocks: Vec<u32> = commit_blocks.clone();
	blocks.sort();
	blocks.dedup();
	let name_of =
		|c: &[u8; 32]| plans.iter().find(|p| &p.commitment == c).map(|p| p.name).unwrap_or("?");
	for block in blocks {
		let events = chain.initialization_events(block + delay)?;
		let commit_hash = chain.rpc.block_hash(block)?;
		let mut expected: Vec<&Plan> = plans
			.iter()
			.zip(&commit_blocks)
			.filter(|(p, b)| **b == block && p.name != "Eve")
			.map(|(p, _)| p)
			.collect();
		expected.sort_by_key(|p| order_key(&p.commitment, &commit_hash));
		let mut executed = vec![];
		for event in events {
			match event {
				RuntimeEvent::Sealed(Sealed::Executed { position, commitment, result, .. }) => {
					println!(
						"  block #{}: position {position}: {} ({})",
						block + delay,
						name_of(&commitment),
						if result.is_ok() { "ok" } else { "failed" }
					);
					executed.push(commitment);
				},
				RuntimeEvent::Sealed(Sealed::Forfeited { commitment, .. }) => println!(
					"  block #{}: {} never revealed, deposit burned",
					block + delay,
					name_of(&commitment)
				),
				_ => {},
			}
		}
		let expected: Vec<[u8; 32]> = expected.iter().map(|p| p.commitment).collect();
		ensure!(executed == expected, "execution order is not the canonical order");
	}
	println!("  ok: execution order = blake2(commitment ‖ commit-block hash), not reveal order");
	Ok(())
}

/// Poll best and finalized heads and report per-block finality latency.
fn finality(rpc: &rpc::Rpc, seconds: u64) -> Result<()> {
	use std::{collections::BTreeMap, time::Duration};
	let started = Instant::now();
	let mut seen = BTreeMap::<u32, Instant>::new();
	let mut finalized = BTreeMap::<u32, Instant>::new();
	let (mut best_seen, mut final_seen) = (rpc.best_number()?, rpc.finalized_number()?);
	while started.elapsed() < Duration::from_secs(seconds) {
		let now = Instant::now();
		let best = rpc.best_number()?;
		for n in best_seen + 1..=best {
			seen.insert(n, now);
		}
		best_seen = best_seen.max(best);
		let fin = rpc.finalized_number()?;
		for n in final_seen + 1..=fin {
			finalized.insert(n, now);
		}
		final_seen = final_seen.max(fin);
		std::thread::sleep(Duration::from_millis(20));
	}
	let mut latencies: Vec<Duration> = finalized
		.iter()
		.filter_map(|(n, at)| seen.get(n).map(|first| at.saturating_duration_since(*first)))
		.collect();
	ensure!(latencies.len() >= 3, "too few blocks were finalized in {seconds}s");
	latencies.sort();
	let pick = |q: f64| latencies[((latencies.len() - 1) as f64 * q).round() as usize];
	let times: Vec<&Instant> = seen.values().collect();
	let interval =
		times.last().unwrap().duration_since(*times[0]) / (times.len() as u32 - 1).max(1);
	println!("blocks seen {}, finalized {} (polling every 20 ms)", seen.len(), latencies.len());
	println!("mean block interval {interval:.0?}");
	println!(
		"time to finality: p50 {:.0?}, p90 {:.0?}, max {:.0?}",
		pick(0.5),
		pick(0.9),
		latencies.last().unwrap()
	);
	Ok(())
}

/// The `mldsa-batch` guest input: `ctx`, then `n` prefixed `(public key, message, signature)`.
fn mldsa_batch_input(items: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
	fn prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
		out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
		out.extend_from_slice(bytes);
	}
	let mut input = vec![];
	prefixed(&mut input, canggu_primitives::ML_DSA_CONTEXT);
	input.extend_from_slice(&(items.len() as u32).to_le_bytes());
	for (public, message, signature) in items {
		prefixed(&mut input, public);
		prefixed(&mut input, message);
		prefixed(&mut input, signature);
	}
	input
}

/// Run the external SP1 prover (`sp1/`) and return `(proof, public values)`.
fn run_sp1_prover(program: &str, input: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
	let dir = std::env::temp_dir().join(format!("canggu-sp1-{}", std::process::id()));
	std::fs::create_dir_all(&dir)?;
	let (input_path, prefix) = (dir.join("input.bin"), dir.join("out"));
	std::fs::write(&input_path, input)?;
	let prover = std::env::var("CANGGU_SP1_PROVER").unwrap_or_else(|_| "canggu-sp1".into());
	println!("  proving with SP1 on this machine's CPU ({prover}); this takes minutes...");
	let started = Instant::now();
	let status = std::process::Command::new(&prover)
		.arg("prove")
		.arg(program)
		.arg(&input_path)
		.arg(&prefix)
		.status()
		.with_context(|| format!("running {prover}; build it in sp1/ or set CANGGU_SP1_PROVER"))?;
	ensure!(status.success(), "{prover} failed");
	let proof = std::fs::read(prefix.with_extension("proof"))?;
	let public_values = std::fs::read(prefix.with_extension("pv"))?;
	println!("  proof ready after {:.1?}", started.elapsed());
	let _ = std::fs::remove_dir_all(&dir);
	Ok((proof, public_values))
}

/// Post-quantum payroll: prove with SP1 that private salaries sum to a public total.
fn zk_sp1(chain: &Chain, from: &MlDsa65Pair, salt: &str, amounts: &[u64]) -> Result<()> {
	ensure!(!amounts.is_empty(), "give at least one amount");
	let salt =
		<sp_runtime::traits::BlakeTwo256 as sp_runtime::traits::Hash>::hash(salt.as_bytes()).0;
	let mut input = salt.to_vec();
	input.extend_from_slice(&(amounts.len() as u32).to_le_bytes());
	amounts.iter().for_each(|a| input.extend_from_slice(&a.to_le_bytes()));
	let (proof, public_values) = run_sp1_prover("payroll", &input)?;
	ensure!(public_values.len() == 52, "unexpected payroll public values");
	let total = u128::from_le_bytes(public_values[4..20].try_into()?);

	let call = RuntimeCall::ZkVerifier(pallet_zk_verifier::Call::submit_sp1_proof {
		program: canggu_primitives::sp1::PAYROLL_VKEY_HASH,
		public_values: public_values.try_into().map_err(|_| anyhow::anyhow!("too long"))?,
		proof: proof.try_into().map_err(|_| anyhow::anyhow!("proof too large"))?,
	});
	let nonce = chain.rpc.next_nonce(&from.account_id())?;
	let xt = chain.sign(from, call, nonce, vec![], 0)?;
	println!("  submitting a {:.2} MB post-quantum proof", xt.encoded_size() as f64 / 1e6);
	report(&chain.submit_and_wait(&xt)?)?;
	println!("  ok: the chain verified that {} private salaries sum to {total}", amounts.len());
	Ok(())
}
