//! Benchmarks and maintenance commands for canggu-sp1.
//!
//! ```text
//! bench vkeys                          write crates/canggu-sp1-verify/vkeys/*.vkey_hash.{bin,hex}
//! bench cycles                         execute-mode cycle counts (with/without Keccak precompile)
//! bench prove <mldsa|payroll> <n> [--save]
//!                                      one compressed proof: timings, size, native verification
//! ```
//!
//! `prove` prints one JSON object and appends it to `bench-results/results.jsonl`. Run it under
//! `/usr/bin/time -l` (see `scripts/bench-ladder.sh`) to get the peak RSS.

use anyhow::{bail, Context, Result};
use canggu_sp1_prover::{
	blake2_256, client, execute, expected_public_values_mldsa, expected_public_values_payroll,
	keccak256, prove, proving_key, testkit, vkey_hash, Program,
};
use std::{
	fs,
	io::Write,
	path::{Path, PathBuf},
	time::{Duration, Instant},
};

fn root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.canonicalize()
		.expect("workspace root")
}

fn main() -> Result<()> {
	let args: Vec<String> = std::env::args().skip(1).collect();
	match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
		["vkeys"] => vkeys(),
		["cycles"] => cycles(),
		["prove", program, n, rest @ ..] => {
			let save = rest.contains(&"--save");
			prove_one(program, n.parse().context("n")?, save)
		},
		_ => bail!("usage: bench vkeys | bench cycles | bench prove <mldsa|payroll> <n> [--save]"),
	}
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vkeys() -> Result<()> {
	let dir = root().join("crates/canggu-sp1-verify/vkeys");
	fs::create_dir_all(&dir)?;
	for program in [Program::MldsaBatch, Program::Payroll] {
		let h = vkey_hash(program)?;
		fs::write(dir.join(format!("{}.vkey_hash.bin", program.name())), &h)?;
		fs::write(dir.join(format!("{}.vkey_hash.hex", program.name())), hex(&h) + "\n")?;
		println!("{}: {} ({} bytes)", program.name(), hex(&h), h.len());
	}
	Ok(())
}

fn payroll_inputs(n: usize) -> ([u8; 32], Vec<u64>) {
	let salt = keccak256(b"canggu/payroll/bench-salt");
	let amounts = (0..n as u64).map(|i| 1_000_000 + i * 7_919).collect();
	(salt, amounts)
}

fn cycles() -> Result<()> {
	println!("| program | n | cycles | cycles/item | keccak permutes | gas |");
	println!("|---|---|---|---|---|---|");
	for n in [1usize, 4, 16] {
		let items = testkit::intent_items(n, testkit::CTX);
		let input = canggu_mldsa::batch::encode_input(testkit::CTX, &items);
		for program in [Program::MldsaBatch, Program::MldsaBatchSoftKeccak] {
			let e = execute(program, input.clone())?;
			println!(
				"| {} | {n} | {} | {} | {} | {} |",
				program.name(),
				e.cycles,
				e.cycles / n as u64,
				e.keccak_permutes,
				e.gas.map_or("-".into(), |g| g.to_string())
			);
		}
	}
	for n in [16usize, 256, 4096, 65536] {
		let (salt, amounts) = payroll_inputs(n);
		let e = execute(Program::Payroll, canggu_mldsa::payroll::encode_input(&salt, &amounts))?;
		println!(
			"| payroll | {n} | {} | {} | {} | {} |",
			e.cycles,
			e.cycles / n as u64,
			e.keccak_permutes,
			e.gas.map_or("-".into(), |g| g.to_string())
		);
	}
	Ok(())
}

/// The SP1 tuning variables in effect (worker counts, buffer and shard sizes), for the record.
fn tuning_env() -> String {
	let mut vars: Vec<String> = std::env::vars()
		.filter(|(k, _)| {
			k.starts_with("SP1_")
				|| [
					"SHARD_SIZE",
					"MEMORY_LIMIT",
					"RAYON_NUM_THREADS",
					"ELEMENT_THRESHOLD",
					"HEIGHT_THRESHOLD",
				]
				.contains(&k.as_str())
		})
		.map(|(k, v)| format!("{k}={v}"))
		.collect();
	vars.sort();
	vars.join(" ")
}

fn prove_one(which: &str, n: usize, save: bool) -> Result<()> {
	let t = Instant::now();
	let _ = client();
	let client_init = t.elapsed();

	let (program, input, expected) = match which {
		"mldsa" => {
			let items = testkit::intent_items(n, testkit::CTX);
			let accounts: Vec<[u8; 32]> = items.iter().map(|(pk, _, _)| blake2_256(pk)).collect();
			let msgs: Vec<Vec<u8>> = items.iter().map(|(_, m, _)| m.clone()).collect();
			let expected = expected_public_values_mldsa(testkit::CTX, &accounts, &msgs);
			let input = canggu_mldsa::batch::encode_input(testkit::CTX, &items);
			(Program::MldsaBatch, input, expected)
		},
		"payroll" => {
			let (salt, amounts) = payroll_inputs(n);
			let total: u128 = amounts.iter().map(|&a| u128::from(a)).sum();
			let mut pre = salt.to_vec();
			amounts.iter().for_each(|a| pre.extend_from_slice(&a.to_le_bytes()));
			let expected = expected_public_values_payroll(n as u32, total, &keccak256(&pre));
			(Program::Payroll, canggu_mldsa::payroll::encode_input(&salt, &amounts), expected)
		},
		_ => bail!("unknown program {which}"),
	};

	let t = Instant::now();
	proving_key(program)?;
	let setup = t.elapsed();

	let t = Instant::now();
	let executed = execute(program, input.clone())?;
	let exec = t.elapsed();

	let t = Instant::now();
	let proved = prove(program, input)?;
	// `prove` re-executes once before proving; subtract that to report proving alone.
	let prove_total = t.elapsed();
	let prove_only = prove_total.saturating_sub(exec);

	anyhow::ensure!(proved.public_values == expected, "public values differ from expectation");
	if let Some(committed) = program.committed_vkey_hash() {
		anyhow::ensure!(proved.vkey_hash == committed, "committed vkey hash is stale");
	}

	// Native verification: first call (includes building the verifier, i.e. machine + vk tree)
	// and the best of a few warm calls.
	let t = Instant::now();
	let ok = canggu_sp1_verify::verify(&proved.proof, &proved.public_values, &proved.vkey_hash);
	let verify_first = t.elapsed();
	anyhow::ensure!(
		ok,
		"verification failed: {:?}",
		canggu_sp1_verify::try_verify(&proved.proof, &proved.public_values, &proved.vkey_hash)
	);
	let mut warm = Vec::new();
	for _ in 0..5 {
		let t = Instant::now();
		assert!(canggu_sp1_verify::verify(&proved.proof, &proved.public_values, &proved.vkey_hash));
		warm.push(t.elapsed());
	}
	warm.sort();

	if save {
		let dir = root().join("fixtures");
		fs::create_dir_all(&dir)?;
		let stem = format!("{}-n{n}", program.name());
		fs::write(dir.join(format!("{stem}.proof")), &proved.proof)?;
		fs::write(dir.join(format!("{stem}.pv")), &proved.public_values)?;
		fs::write(dir.join(format!("{stem}.vkey")), &proved.vkey_hash)?;
	}

	let ms = |d: Duration| d.as_secs_f64() * 1e3;
	let line = format!(
		concat!(
			"{{\"program\":\"{}\",\"n\":{},\"cycles\":{},\"gas\":{},\"keccak_permutes\":{},",
			"\"client_init_s\":{:.2},\"setup_s\":{:.2},\"execute_ms\":{:.1},",
			"\"prove_s\":{:.2},\"proof_bytes\":{},\"verify_first_ms\":{:.1},",
			"\"verify_warm_min_ms\":{:.1},\"verify_warm_median_ms\":{:.1},",
			"\"input_bytes_equiv\":{},\"threads\":{},\"env\":\"{}\"}}"
		),
		program.name(),
		n,
		executed.cycles,
		executed.gas.map_or("null".into(), |g| g.to_string()),
		executed.keccak_permutes,
		client_init.as_secs_f64(),
		setup.as_secs_f64(),
		ms(exec),
		prove_only.as_secs_f64(),
		proved.proof.len(),
		ms(verify_first),
		ms(warm[0]),
		ms(warm[warm.len() / 2]),
		if program == Program::MldsaBatch { n * (1952 + 3309) } else { 8 * n },
		std::thread::available_parallelism().map_or(0, |p| p.get()),
		tuning_env(),
	);
	println!("{line}");
	let dir = root().join("bench-results");
	fs::create_dir_all(&dir)?;
	writeln!(
		fs::OpenOptions::new()
			.create(true)
			.append(true)
			.open(dir.join("results.jsonl"))?,
		"{line}"
	)?;
	Ok(())
}
