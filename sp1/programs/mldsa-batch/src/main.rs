//! SP1 guest: verify a batch of ML-DSA-65 signatures under one FIPS 204 context string.
//!
//! Input: one blob (see `canggu_mldsa::batch`). Every signature must verify; the first invalid one
//! panics, so no proof can exist for a batch containing it. Public values (68 bytes):
//! `n: u32 LE | keccak256(ctx) | keccak256(concat_i(blake2_256(pk_i) | keccak256(msg_i)))`.

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
	let input = sp1_zkvm::io::read_vec();
	let public_values = canggu_mldsa::batch::run(&input);
	sp1_zkvm::io::commit_slice(&public_values);
}
