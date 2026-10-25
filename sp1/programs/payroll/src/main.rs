//! SP1 guest: private payroll. Knows `salt` and `amounts`; reveals only
//! `n: u32 LE | total: u128 LE | keccak256(salt | amounts as u64 LE)` (52 bytes).

#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
	let input = sp1_zkvm::io::read_vec();
	let public_values = canggu_mldsa::payroll::run(&input);
	sp1_zkvm::io::commit_slice(&public_values);
}
