//! Acceptance and rejection tests against committed proofs (`fixtures/`, produced by
//! `bench prove <mldsa|payroll> <n> --save`).

use canggu_sp1_verify::{
	try_verify, verify, MLDSA_BATCH_PUBLIC_VALUES_BYTES, MLDSA_BATCH_VKEY_HASH,
	PAYROLL_PUBLIC_VALUES_BYTES, PAYROLL_VKEY_HASH,
};
use std::{path::PathBuf, time::Instant};

struct Fixture {
	proof: Vec<u8>,
	pv: Vec<u8>,
	vkey: Vec<u8>,
}

fn load(stem: &str) -> Fixture {
	let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
	let read = |ext: &str| {
		std::fs::read(dir.join(format!("{stem}.{ext}")))
			.unwrap_or_else(|e| panic!("fixture {stem}.{ext}: {e}"))
	};
	Fixture { proof: read("proof"), pv: read("pv"), vkey: read("vkey") }
}

fn mldsa() -> Fixture {
	load("mldsa-batch-n4")
}

fn payroll() -> Fixture {
	load("payroll-n16")
}

#[test]
fn valid_proofs_verify() {
	for (f, vkey, len) in [
		(mldsa(), MLDSA_BATCH_VKEY_HASH, MLDSA_BATCH_PUBLIC_VALUES_BYTES),
		(payroll(), PAYROLL_VKEY_HASH, PAYROLL_PUBLIC_VALUES_BYTES),
	] {
		assert_eq!(f.vkey, vkey, "fixture made with a different ELF than the committed vkey");
		assert_eq!(f.pv.len(), len);
		try_verify(&f.proof, &f.pv, &f.vkey).expect("valid proof");
		let t = Instant::now();
		assert!(verify(&f.proof, &f.pv, &f.vkey));
		println!("verified {} byte proof in {:?}", f.proof.len(), t.elapsed());
	}
}

#[test]
fn wrong_public_values_are_rejected() {
	let f = mldsa();
	for i in [0, 3, 4, 35, 36, 67] {
		let mut pv = f.pv.clone();
		pv[i] ^= 1;
		assert!(!verify(&f.proof, &pv, &f.vkey), "flipped public value byte {i}");
	}
	assert!(!verify(&f.proof, &f.pv[..67], &f.vkey));
	let mut longer = f.pv.clone();
	longer.push(0);
	assert!(!verify(&f.proof, &longer, &f.vkey));
	assert!(!verify(&f.proof, &[], &f.vkey));
	// Another program's (valid) public values.
	assert!(!verify(&f.proof, &payroll().pv, &f.vkey));
}

#[test]
fn wrong_vkey_is_rejected() {
	let m = mldsa();
	let p = payroll();
	// Each proof under the other program's vkey hash.
	assert!(!verify(&m.proof, &m.pv, PAYROLL_VKEY_HASH));
	assert!(!verify(&p.proof, &p.pv, MLDSA_BATCH_VKEY_HASH));
	// Bit flips in the vkey hash, wrong lengths.
	for i in 0..m.vkey.len() {
		let mut vk = m.vkey.clone();
		vk[i] ^= 1 << (i % 8);
		assert!(!verify(&m.proof, &m.pv, &vk), "flipped vkey byte {i}");
	}
	assert!(!verify(&m.proof, &m.pv, &m.vkey[..31]));
	assert!(!verify(&m.proof, &m.pv, &[]));
	let mut longer = m.vkey.clone();
	longer.push(0);
	assert!(!verify(&m.proof, &m.pv, &longer));
	// Non-canonical field elements in the vkey hash: word + p decodes to the same element.
	for w in 0..8 {
		let mut vk = m.vkey.clone();
		let x = u32::from_le_bytes(vk[4 * w..4 * w + 4].try_into().unwrap());
		if let Some(y) = x.checked_add(0x7f00_0001) {
			vk[4 * w..4 * w + 4].copy_from_slice(&y.to_le_bytes());
			assert!(!verify(&m.proof, &m.pv, &vk), "non-canonical vkey word {w}");
		}
	}
}

#[test]
fn tampered_proofs_are_rejected() {
	let f = mldsa();
	let len = f.proof.len();
	// Spread bit flips over the whole proof, plus the very beginning and end (enum tag, lengths,
	// merkle path). Positions are deterministic so failures are reproducible.
	let mut positions: Vec<usize> =
		(0..64).map(|k| k * len / 64 + (k * 7919) % (len / 64)).collect();
	positions.extend([0, 1, 4, 8, 16, len - 1, len - 8, len - 33]);
	let t = Instant::now();
	let mut rejected = 0;
	for &pos in &positions {
		let mut proof = f.proof.clone();
		proof[pos] ^= 0x10;
		assert!(!verify(&proof, &f.pv, &f.vkey), "flip at byte {pos} of {len} accepted");
		rejected += 1;
	}
	println!("{rejected} tampered proofs rejected in {:?}", t.elapsed());
	// Truncations and extensions.
	for cut in [0, 1, 8, len / 2, len - 1] {
		assert!(!verify(&f.proof[..cut], &f.pv, &f.vkey), "truncated to {cut}");
	}
	// Trailing bytes: bincode would ignore them; the canonical-encoding check must not.
	for extra in [&[0u8][..], &[0; 8], &[0xff; 100]] {
		let mut longer = f.proof.clone();
		longer.extend_from_slice(extra);
		assert!(!verify(&longer, &f.pv, &f.vkey), "{} trailing bytes accepted", extra.len());
	}
	// Swapping in the other program's proof.
	let p = payroll();
	assert!(!verify(&p.proof, &f.pv, &f.vkey));
}

/// Find the bincode encoding of a non-zero field element inside the proof and replace it by
/// `x + p`: the decoded proof is identical, so only the canonical-encoding check can reject it.
#[test]
fn non_canonical_field_elements_are_rejected() {
	let f = mldsa();
	let (mut found, mut raw_accepted) = (0, 0);
	// Proof bytes are mostly 4-byte little-endian field elements; scan a deterministic sample
	// of aligned positions for words that are valid (< p) and can take + p without overflow.
	// The proof ends with the vk Merkle path (`[KoalaBear; 8]` digests), then sample the rest.
	let len = f.proof.len();
	let tail = (1..=16).map(|k| len - 4 * k);
	for pos in tail.chain((len / 2..len - 4).step_by(4 * 997)) {
		let x = u32::from_le_bytes(f.proof[pos..pos + 4].try_into().unwrap());
		let Some(y) = x.checked_add(0x7f00_0001) else { continue };
		if x == 0 || x >= 0x7f00_0001 {
			continue;
		}
		let mut proof = f.proof.clone();
		proof[pos..pos + 4].copy_from_slice(&y.to_le_bytes());
		assert!(!verify(&proof, &f.pv, &f.vkey), "x + p at byte {pos} accepted");
		// Without the canonical check, `sp1-verifier` itself accepts the altered bytes when the
		// word really is a field element (other positions are lengths, indices, ...).
		raw_accepted += usize::from(
			sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(
				&proof, &f.pv, &f.vkey,
			)
			.is_ok(),
		);
		found += 1;
		if found == 20 {
			break;
		}
	}
	assert!(found >= 5, "not enough candidate positions ({found})");
	println!("{found} non-canonical variants rejected; raw sp1-verifier accepted {raw_accepted}");
	assert!(raw_accepted > 0, "the malleability this test guards against was not reproduced");
}

#[test]
fn garbage_never_panics() {
	let mut x = 0x1234_5678_9abc_def0u64;
	let mut next = || {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
		x
	};
	for len in [0usize, 1, 3, 4, 7, 8, 9, 16, 31, 32, 33, 64, 100, 1000, 10_000, 100_000] {
		let garbage: Vec<u8> = (0..len).map(|_| next() as u8).collect();
		assert!(!verify(&garbage, &garbage, &garbage));
		assert!(!verify(&garbage, &[0; 68], MLDSA_BATCH_VKEY_HASH));
	}
	// Huge declared lengths in the bincode prefix must not allocate unboundedly or panic.
	let mut evil = vec![1u8, 0, 0, 0];
	evil.extend_from_slice(&[0xff; 64]);
	assert!(!verify(&evil, &[0; 68], MLDSA_BATCH_VKEY_HASH));
}
