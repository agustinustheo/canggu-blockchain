//! Keccak-f[1600], SHAKE128/SHAKE256 (FIPS 202) and the original Keccak-256 hash.
//!
//! Sponge adapted from `canggu/gpu/src/keccak.rs`. The permutation is [`keccak_f1600`]:
//! inside the SP1 zkVM (with the default `precompile` feature) it is a single `ecall` into SP1's
//! Keccak-permute precompile, which is proven by a dedicated AIR instead of ~6,400 RISC-V
//! cycles (measured with the unrolled software permutation). Everything above the permutation
//! (padding, rate handling, squeezing) is plain Rust and identical on every target, so host
//! tests exercise the very same sponge code.

/// SHAKE128 rate in bytes.
pub const SHAKE128_RATE: usize = 168;
/// SHAKE256 (and Keccak-256) rate in bytes.
pub const SHAKE256_RATE: usize = 136;

/// The Keccak-f[1600] permutation in software: RustCrypto `keccak` (fully unrolled). Used on the
/// host and by the guest when the `precompile` feature is off.
#[inline(always)]
pub fn keccak_f1600_soft(state: &mut [u64; 25]) {
	keccak::f1600(state)
}

/// The Keccak-f[1600] permutation (SP1 precompile inside the zkVM).
#[cfg(all(target_os = "zkvm", feature = "precompile"))]
#[inline(always)]
pub fn keccak_f1600(state: &mut [u64; 25]) {
	extern "C" {
		// Provided (`#[no_mangle]`) by `sp1-zkvm`, which every guest links. Declaring it here
		// keeps this crate free of an SP1 dependency.
		fn syscall_keccak_permute(state: *mut [u64; 25]);
	}
	// SAFETY: `state` is a valid, 8-byte aligned `[u64; 25]` for the duration of the call; the
	// syscall reads and writes exactly those 200 bytes.
	unsafe { syscall_keccak_permute(state) }
}

/// The Keccak-f[1600] permutation (software).
#[cfg(not(all(target_os = "zkvm", feature = "precompile")))]
#[inline(always)]
pub fn keccak_f1600(state: &mut [u64; 25]) {
	keccak_f1600_soft(state)
}

/// An incremental Keccak sponge (absorb any number of times, then squeeze any number of times).
///
/// `pad` is the first padding byte: `0x1F` for SHAKE (FIPS 202), `0x01` for the original Keccak
/// submission used by Ethereum and `sp_io::hashing::keccak_256`.
#[derive(Clone)]
pub struct Sponge {
	state: [u64; 25],
	rate: usize,
	pad: u8,
	/// Byte offset into the current block (absorb position, then squeeze position).
	pos: usize,
	squeezing: bool,
}

impl Sponge {
	const fn new(rate: usize, pad: u8) -> Self {
		Self { state: [0; 25], rate, pad, pos: 0, squeezing: false }
	}

	/// A fresh SHAKE128 instance.
	pub const fn shake128() -> Self {
		Self::new(SHAKE128_RATE, 0x1F)
	}

	/// A fresh SHAKE256 instance.
	pub const fn shake256() -> Self {
		Self::new(SHAKE256_RATE, 0x1F)
	}

	/// A fresh Keccak-256 instance (squeeze 32 bytes).
	pub const fn keccak256() -> Self {
		Self::new(SHAKE256_RATE, 0x01)
	}

	#[inline(always)]
	fn xor_byte(&mut self, i: usize, b: u8) {
		self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
	}

	#[inline(always)]
	fn get_byte(&self, i: usize) -> u8 {
		(self.state[i / 8] >> (8 * (i % 8))) as u8
	}

	/// Absorb `data`. Must not be called after squeezing started.
	pub fn absorb(&mut self, mut data: &[u8]) -> &mut Self {
		assert!(!self.squeezing, "absorb after squeeze");
		while !data.is_empty() {
			if self.pos.is_multiple_of(8) && data.len() >= 8 {
				// Fast path: whole little-endian lanes up to the end of the block.
				let lanes = ((self.rate - self.pos) / 8).min(data.len() / 8);
				for (l, chunk) in data[..8 * lanes].chunks_exact(8).enumerate() {
					let lane = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
					self.state[self.pos / 8 + l] ^= lane;
				}
				self.pos += 8 * lanes;
				data = &data[8 * lanes..];
			} else {
				self.xor_byte(self.pos, data[0]);
				self.pos += 1;
				data = &data[1..];
			}
			if self.pos == self.rate {
				keccak_f1600(&mut self.state);
				self.pos = 0;
			}
		}
		self
	}

	fn finalize(&mut self) {
		self.xor_byte(self.pos, self.pad);
		self.xor_byte(self.rate - 1, 0x80);
		keccak_f1600(&mut self.state);
		self.pos = 0;
		self.squeezing = true;
	}

	/// Squeeze `out.len()` bytes.
	pub fn squeeze(&mut self, out: &mut [u8]) {
		if !self.squeezing {
			self.finalize();
		}
		for o in out {
			if self.pos == self.rate {
				keccak_f1600(&mut self.state);
				self.pos = 0;
			}
			*o = self.get_byte(self.pos);
			self.pos += 1;
		}
	}

	/// Squeeze a single byte.
	pub fn squeeze_byte(&mut self) -> u8 {
		let mut b = [0u8; 1];
		self.squeeze(&mut b);
		b[0]
	}

	/// Finish a Keccak-256 computation.
	pub fn finish32(mut self) -> [u8; 32] {
		let mut out = [0u8; 32];
		self.squeeze(&mut out);
		out
	}
}

/// Keccak-256 (`sp_io::hashing::keccak_256`, Ethereum's `keccak256`).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
	let mut h = Sponge::keccak256();
	h.absorb(data);
	h.finish32()
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate std;
	use std::{format, string::String};

	fn hex(b: &[u8]) -> String {
		b.iter().map(|x| format!("{x:02x}")).collect()
	}

	#[test]
	fn known_vectors() {
		let mut out = [0u8; 32];
		Sponge::shake128().squeeze(&mut out);
		assert_eq!(hex(&out), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
		Sponge::shake256().squeeze(&mut out);
		assert_eq!(hex(&out), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
		assert_eq!(
			hex(&keccak256(b"")),
			"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
		);
	}

	#[test]
	fn incremental_absorb_and_squeeze_match_one_shot() {
		let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
		let mut a = Sponge::shake256();
		a.absorb(&data);
		let mut one = [0u8; 400];
		a.squeeze(&mut one);

		let mut b = Sponge::shake256();
		for chunk in data.chunks(37) {
			b.absorb(chunk);
		}
		let mut two = [0u8; 400];
		for chunk in two.chunks_mut(13) {
			b.squeeze(chunk);
		}
		assert_eq!(one, two);
	}
}
