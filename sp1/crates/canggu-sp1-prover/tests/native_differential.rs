//! Native (host) differential test of the guest's ML-DSA-65 verifier (`canggu_mldsa::verify`,
//! software Keccak) against RustCrypto `ml-dsa` 0.1.1 on a large corpus. The zkVM tests
//! (`tests/zkvm.rs`) then show that the guest build behaves identically inside SP1.

use canggu_sp1_prover::testkit::{self, ml_dsa_verify, Rng, CTX};
use std::collections::BTreeMap;

#[test]
fn guest_verifier_matches_ml_dsa() {
	let valid = testkit::valid_cases(600, CTX, 42);
	let mut rng = Rng(7);
	let invalid = testkit::invalid_cases(&valid, 3000, &mut rng);
	let mut tally: BTreeMap<(&str, bool), usize> = BTreeMap::new();
	let mut check = |c: &testkit::Case, ctx: &[u8], category: &'static str| {
		let want = ml_dsa_verify(&c.public, &c.msg, &c.signature, ctx);
		let got = canggu_mldsa::verify(&c.public, &c.msg, &c.signature, ctx);
		assert_eq!(got, want, "{category}: guest {got} vs ml-dsa {want}");
		*tally.entry((category, got)).or_default() += 1;
	};
	for c in &valid {
		check(c, CTX, "valid");
	}
	for c in &invalid {
		check(c, CTX, c.category);
	}
	// Valid signatures under other contexts (wrong, empty, maximum length, too long).
	for c in &valid[..100] {
		check(c, b"canggu/tx/v2", "wrong ctx");
		check(c, b"", "empty ctx");
		check(c, &[b'x'; 256], "ctx > 255 bytes");
	}
	let ctx255 = [0xA5u8; 255];
	for c in testkit::valid_cases(40, &ctx255, 9) {
		check(&c, &ctx255, "valid, ctx 255 bytes");
	}
	for c in testkit::valid_cases(40, b"", 10) {
		check(&c, b"", "valid, empty ctx");
	}
	for ((category, verdict), count) in &tally {
		println!("{verdict:<5} {count:>5}  {category}");
	}
	assert_eq!(tally[&("valid", true)], 600);
	assert!(!tally.contains_key(&("valid", false)));
	// Every corruption category must actually be rejected (not just agree with ml-dsa).
	for (category, verdict) in tally.keys() {
		if !category.starts_with("valid") {
			assert!(!verdict, "{category} accepted");
		}
	}
}
