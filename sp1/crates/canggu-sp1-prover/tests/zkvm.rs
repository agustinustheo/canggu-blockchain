//! Execute-mode tests of the real guest ELFs inside the SP1 executor (no proving).
//!
//! * At least 200 valid signatures: execution succeeds and the public values equal what the
//!   chain would recompute (checked with independent Keccak/BLAKE2b implementations).
//! * At least 200 corrupted signatures (each one rejected by `ml-dsa`): every execution fails.
//! * Payroll public values layout; malformed inputs fail; committed vkey hashes are current.
//!
//! Run with `cargo test --release -p canggu-sp1-prover --test zkvm -- --nocapture`.

use canggu_sp1_prover::{
	execute, execute_mldsa_batch, execute_payroll, expected_public_values_mldsa, testkit,
	testkit::{ml_dsa_verify, Rng, CTX},
	vkey_hash, Program,
};
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, time::Instant};

/// Independent `sp_crypto_hashing::blake2_256` (that crate uses `blake2b_simd` as well).
fn blake2_256(data: &[u8]) -> [u8; 32] {
	let h = blake2b_simd::Params::new().hash_length(32).hash(data);
	h.as_bytes().try_into().unwrap()
}

fn keccak(data: &[u8]) -> [u8; 32] {
	Keccak256::digest(data).into()
}

/// The public values layout, written out by hand from the spec.
fn spec_public_values(ctx: &[u8], items: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
	let mut concat = Vec::new();
	for (pk, msg, _) in items {
		concat.extend_from_slice(&blake2_256(pk));
		concat.extend_from_slice(&keccak(msg));
	}
	let mut out = (items.len() as u32).to_le_bytes().to_vec();
	out.extend_from_slice(&keccak(ctx));
	out.extend_from_slice(&keccak(&concat));
	out
}

#[test]
fn valid_batches_execute_and_commit_expected_public_values() {
	let valid = testkit::valid_cases(240, CTX, 42);
	let t = Instant::now();
	let mut cycles = 0;
	for batch in valid.chunks(24) {
		let items: Vec<_> = batch.iter().map(testkit::Case::item).collect();
		for (pk, msg, sig) in &items {
			assert!(ml_dsa_verify(pk, msg, sig, CTX));
		}
		let e = execute_mldsa_batch(CTX, &items).expect("valid batch must execute");
		let spec = spec_public_values(CTX, &items);
		assert_eq!(e.public_values, spec);
		let accounts: Vec<[u8; 32]> = items.iter().map(|(pk, _, _)| blake2_256(pk)).collect();
		let msgs: Vec<Vec<u8>> = items.iter().map(|(_, m, _)| m.clone()).collect();
		assert_eq!(expected_public_values_mldsa(CTX, &accounts, &msgs), spec);
		cycles += e.cycles;
	}
	println!(
		"240 valid signatures in 10 batches: {} cycles/signature, {:?}",
		cycles / 240,
		t.elapsed()
	);
}

#[test]
fn other_contexts() {
	// Empty and maximum-length contexts verify; the public values carry keccak256(ctx).
	for ctx in [&b""[..], &[0xA5u8; 255][..]] {
		let items: Vec<_> = testkit::valid_cases(3, ctx, 5).iter().map(|c| c.item()).collect();
		let e = execute_mldsa_batch(ctx, &items).unwrap();
		assert_eq!(e.public_values, spec_public_values(ctx, &items));
	}
	// Correct signatures under a different context are rejected.
	let items: Vec<_> = testkit::valid_cases(2, CTX, 6).iter().map(|c| c.item()).collect();
	assert!(execute_mldsa_batch(b"canggu/tx/v2", &items).is_err());
	assert!(execute_mldsa_batch(&[b'x'; 256], &items).is_err());
}

#[test]
fn empty_batch() {
	let e = execute_mldsa_batch(CTX, &[]).unwrap();
	assert_eq!(e.public_values, spec_public_values(CTX, &[]));
}

#[test]
fn corrupted_signatures_fail_execution() {
	let valid = testkit::valid_cases(64, CTX, 43);
	let mut rng = Rng(8);
	let invalid = testkit::invalid_cases(&valid, 220, &mut rng);
	let t = Instant::now();
	let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
	for (k, bad) in invalid.iter().enumerate() {
		assert!(
			!ml_dsa_verify(&bad.public, &bad.msg, &bad.signature, CTX),
			"corpus case {k} ({}) is actually valid",
			bad.category
		);
		// Hide the bad item between valid ones, at a varying position.
		let mut items: Vec<_> = valid[k % 60..k % 60 + 3].iter().map(|c| c.item()).collect();
		items.insert(k % 4, bad.item());
		let r = execute_mldsa_batch(CTX, &items);
		assert!(r.is_err(), "case {k} ({}) executed successfully", bad.category);
		*tally.entry(bad.category).or_default() += 1;
	}
	for (category, count) in &tally {
		println!("rejected {count:>4}  {category}");
	}
	println!("220 corrupted batches rejected in {:?}", t.elapsed());
}

#[test]
fn malformed_input_fails() {
	let items: Vec<_> = testkit::valid_cases(1, CTX, 44).iter().map(|c| c.item()).collect();
	let input = canggu_mldsa::batch::encode_input(CTX, &items);
	// Truncated, trailing byte, wrong count.
	assert!(execute(Program::MldsaBatch, input[..input.len() - 1].to_vec()).is_err());
	let mut longer = input.clone();
	longer.push(0);
	assert!(execute(Program::MldsaBatch, longer).is_err());
	let mut count = input.clone();
	count[4 + CTX.len()] = 2;
	assert!(execute(Program::MldsaBatch, count).is_err());
	assert!(execute(Program::MldsaBatch, Vec::new()).is_err());
}

#[test]
fn soft_keccak_build_agrees() {
	let items: Vec<_> = testkit::valid_cases(4, CTX, 45).iter().map(|c| c.item()).collect();
	let input = canggu_mldsa::batch::encode_input(CTX, &items);
	let a = execute(Program::MldsaBatch, input.clone()).unwrap();
	let b = execute(Program::MldsaBatchSoftKeccak, input).unwrap();
	assert_eq!(a.public_values, b.public_values);
	assert!(a.keccak_permutes > 0 && b.keccak_permutes == 0);
	println!("cycles: precompile {} vs software {}", a.cycles, b.cycles);
}

#[test]
fn payroll_public_values() {
	let salt = [7u8; 32];
	for amounts in [vec![], vec![0], vec![1, 2, 3], vec![u64::MAX; 1000], (0..5000).collect()] {
		let e = execute_payroll(salt, &amounts).unwrap();
		let total: u128 = amounts.iter().map(|&a| u128::from(a)).sum();
		let mut pre = salt.to_vec();
		amounts.iter().for_each(|a| pre.extend_from_slice(&a.to_le_bytes()));
		let mut spec = (amounts.len() as u32).to_le_bytes().to_vec();
		spec.extend_from_slice(&total.to_le_bytes());
		spec.extend_from_slice(&keccak(&pre));
		assert_eq!(e.public_values, spec);
		assert_eq!(e.public_values, canggu_mldsa::payroll::public_values(&salt, &amounts));
	}
	// Truncated amounts.
	let input = canggu_mldsa::payroll::encode_input(&salt, &[1, 2]);
	assert!(execute(Program::Payroll, input[..input.len() - 1].to_vec()).is_err());
}

#[test]
fn committed_vkey_hashes_are_current() {
	for program in [Program::MldsaBatch, Program::Payroll] {
		assert_eq!(
			vkey_hash(program).unwrap(),
			program.committed_vkey_hash().unwrap(),
			"{}: run `bench vkeys`",
			program.name()
		);
	}
}
