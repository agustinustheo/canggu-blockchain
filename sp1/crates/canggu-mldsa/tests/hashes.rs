//! The sponge, SHAKE and Keccak-256 against RustCrypto `sha3` on many lengths (all block-boundary
//! cases of both rates).

use canggu_mldsa::keccak::Sponge;
use sha3::{
	digest::{ExtendableOutput, Update, XofReader},
	Digest, Keccak256, Shake128, Shake256,
};

fn data(len: usize) -> Vec<u8> {
	(0..len)
		.map(|i| (i as u32).wrapping_mul(2654435761).wrapping_shr(13) as u8)
		.collect()
}

#[test]
fn keccak256_matches_sha3() {
	for len in (0..700).chain([1952, 5261, 100_000]) {
		let d = data(len);
		let want: [u8; 32] = Keccak256::digest(&d).into();
		assert_eq!(canggu_mldsa::keccak256(&d), want, "len {len}");
	}
}

#[test]
fn shake_matches_sha3() {
	for len in (0..400).chain([1952, 3309]) {
		let d = data(len);
		for out_len in [1, 48, 64, 136, 168, 500] {
			let mut want = vec![0u8; out_len];
			let mut got = vec![0u8; out_len];
			let mut x = Shake256::default();
			x.update(&d);
			x.finalize_xof().read(&mut want);
			Sponge::shake256().absorb(&d).squeeze(&mut got);
			assert_eq!(got, want, "shake256 len {len} out {out_len}");
			let mut x = Shake128::default();
			x.update(&d);
			x.finalize_xof().read(&mut want);
			Sponge::shake128().absorb(&d).squeeze(&mut got);
			assert_eq!(got, want, "shake128 len {len} out {out_len}");
		}
	}
}
