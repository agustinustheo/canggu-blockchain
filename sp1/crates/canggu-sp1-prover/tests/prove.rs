//! End-to-end: prove, then verify with `canggu-sp1-verify` exactly as a chain would (from the
//! committed vkey hash and public values recomputed from what the chain knows).
//!
//! Slow (about 1-2 minutes and ~15 GB RAM each), hence ignored by default:
//! `cargo test --release -p canggu-sp1-prover --test prove -- --ignored --nocapture`.

use canggu_sp1_prover::{
	blake2_256, expected_public_values_mldsa, expected_public_values_payroll, keccak256,
	prove_mldsa_batch, prove_payroll, testkit, Program,
};

#[test]
#[ignore = "proves (minutes, ~15 GB RAM)"]
fn mldsa_batch_end_to_end() {
	let ctx = testkit::CTX;
	let items = testkit::intent_items(2, ctx);
	let proved = prove_mldsa_batch(ctx, &items).unwrap();

	// What the runtime knows: each sender's AccountId and message, never keys or signatures.
	let accounts: Vec<[u8; 32]> = items.iter().map(|(pk, _, _)| blake2_256(pk)).collect();
	let msgs: Vec<Vec<u8>> = items.iter().map(|(_, m, _)| m.clone()).collect();
	let pv = expected_public_values_mldsa(ctx, &accounts, &msgs);
	assert_eq!(proved.public_values, pv);
	assert_eq!(proved.vkey_hash, Program::MldsaBatch.committed_vkey_hash().unwrap());
	assert!(canggu_sp1_verify::verify(
		&proved.proof,
		&pv,
		canggu_sp1_verify::MLDSA_BATCH_VKEY_HASH
	));
	// A different message order is a different statement.
	let swapped = expected_public_values_mldsa(
		ctx,
		&[accounts[1], accounts[0]],
		&[msgs[1].clone(), msgs[0].clone()],
	);
	assert!(!canggu_sp1_verify::verify(
		&proved.proof,
		&swapped,
		canggu_sp1_verify::MLDSA_BATCH_VKEY_HASH
	));

	// An invalid signature cannot be proven at all.
	let mut bad = items.clone();
	bad[1].2[100] ^= 1;
	assert!(prove_mldsa_batch(ctx, &bad).is_err());
}

#[test]
#[ignore = "proves (minutes, ~15 GB RAM)"]
fn payroll_end_to_end() {
	let salt = [42u8; 32];
	let amounts = [5_000u64, 7_250, 12_000];
	let proved = prove_payroll(salt, &amounts).unwrap();
	let mut pre = salt.to_vec();
	amounts.iter().for_each(|a| pre.extend_from_slice(&a.to_le_bytes()));
	let pv = expected_public_values_payroll(3, 24_250, &keccak256(&pre));
	assert_eq!(proved.public_values, pv);
	assert!(canggu_sp1_verify::verify(&proved.proof, &pv, canggu_sp1_verify::PAYROLL_VKEY_HASH));
	let wrong_total = expected_public_values_payroll(3, 24_251, &keccak256(&pre));
	assert!(!canggu_sp1_verify::verify(
		&proved.proof,
		&wrong_total,
		canggu_sp1_verify::PAYROLL_VKEY_HASH
	));
}
