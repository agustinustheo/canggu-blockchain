//! Minimal Keccak-f[1600] and SHAKE128/SHAKE256 (FIPS 202).
//!
//! This is deliberately the same textbook formulation that the Metal shader uses (`KECCAK_*`
//! tables and round structure in `shaders/verify.metal`), so that the pure-Rust reference
//! pipeline mirrors the GPU code path rather than delegating to a third-party sponge.

/// Round constants for the iota step.
pub(crate) const ROUND_CONSTANTS: [u64; 24] = [
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
];

/// Rotation offsets for the combined rho/pi step, in pi traversal order.
pub(crate) const RHO: [u32; 24] =
	[1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

/// Lane traversal order for the combined rho/pi step.
pub(crate) const PI: [usize; 24] =
	[10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

/// SHAKE128 rate in bytes.
pub(crate) const SHAKE128_RATE: usize = 168;
/// SHAKE256 rate in bytes.
pub(crate) const SHAKE256_RATE: usize = 136;

/// `(destination lane, rotation)` for every source lane of the combined rho/pi step, derived
/// from the cyclic [`PI`]/[`RHO`] formulation.
pub(crate) const RHO_PI: [(usize, u32); 25] = {
	let mut t = [(0usize, 0u32); 25];
	let mut src = 1;
	let mut i = 0;
	while i < 24 {
		t[src] = (PI[i], RHO[i]);
		src = PI[i];
		i += 1;
	}
	t
};

/// The Keccak-f[1600] permutation.
///
/// Rho and pi are applied as one explicit lane permutation ([`RHO_PI`]), exactly like the
/// shader, so that the compiler keeps the whole state in registers.
pub(crate) fn keccak_f1600(state: &mut [u64; 25]) {
	macro_rules! rho_pi {
		($st:ident, $b:ident; $($i:literal)*) => {
			$( $b[RHO_PI[$i].0] = $st[$i].rotate_left(RHO_PI[$i].1); )*
		};
	}
	let mut st = *state;
	for rc in ROUND_CONSTANTS {
		// Theta.
		let mut c = [0u64; 5];
		for x in 0..5 {
			c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
		}
		for x in 0..5 {
			let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
			for y in 0..5 {
				st[x + 5 * y] ^= d;
			}
		}
		// Rho and pi.
		let mut b = [0u64; 25];
		rho_pi!(st, b; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24);
		// Chi.
		for y in 0..5 {
			for x in 0..5 {
				st[5 * y + x] = b[5 * y + x] ^ (!b[5 * y + (x + 1) % 5] & b[5 * y + (x + 2) % 5]);
			}
		}
		// Iota.
		st[0] ^= rc;
	}
	*state = st;
}

/// An incremental SHAKE sponge (absorb any number of times, then squeeze any number of times).
#[derive(Clone)]
pub(crate) struct Shake {
	state: [u64; 25],
	rate: usize,
	/// Byte offset into the current block (absorb position, then squeeze position).
	pos: usize,
	squeezing: bool,
}

impl Shake {
	/// A fresh SHAKE128 instance (the lattice stage absorbs its fixed-size SHAKE128 input
	/// directly into the state, so this is only used by tests).
	#[cfg(test)]
	pub(crate) fn v128() -> Self {
		Self { state: [0; 25], rate: SHAKE128_RATE, pos: 0, squeezing: false }
	}

	/// A fresh SHAKE256 instance.
	pub(crate) fn v256() -> Self {
		Self { state: [0; 25], rate: SHAKE256_RATE, pos: 0, squeezing: false }
	}

	fn xor_byte(&mut self, i: usize, b: u8) {
		self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
	}

	fn get_byte(&self, i: usize) -> u8 {
		(self.state[i / 8] >> (8 * (i % 8))) as u8
	}

	/// Absorb `data`. Must not be called after squeezing started.
	pub(crate) fn absorb(&mut self, mut data: &[u8]) -> &mut Self {
		debug_assert!(!self.squeezing, "absorb after squeeze");
		while !data.is_empty() {
			if self.pos.is_multiple_of(8) && data.len() >= 8 {
				// Fast path: a whole little-endian lane.
				let lane = u64::from_le_bytes(data[..8].try_into().expect("8 bytes"));
				self.state[self.pos / 8] ^= lane;
				self.pos += 8;
				data = &data[8..];
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
		// SHAKE domain separation (0x1F) and the final bit of pad10*1.
		self.xor_byte(self.pos, 0x1F);
		self.xor_byte(self.rate - 1, 0x80);
		keccak_f1600(&mut self.state);
		self.pos = 0;
		self.squeezing = true;
	}

	/// Squeeze `out.len()` bytes.
	pub(crate) fn squeeze(&mut self, out: &mut [u8]) {
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
	pub(crate) fn squeeze_byte(&mut self) -> u8 {
		let mut b = [0u8; 1];
		self.squeeze(&mut b);
		b[0]
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(b: &[u8]) -> String {
		b.iter().map(|x| format!("{x:02x}")).collect()
	}

	#[test]
	fn shake_empty_vectors() {
		let mut out = [0u8; 32];
		Shake::v128().squeeze(&mut out);
		assert_eq!(hex(&out), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
		Shake::v256().squeeze(&mut out);
		assert_eq!(hex(&out), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
	}

	#[test]
	fn incremental_absorb_and_squeeze_match_one_shot() {
		let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
		let mut a = Shake::v256();
		a.absorb(&data);
		let mut one = [0u8; 400];
		a.squeeze(&mut one);

		let mut b = Shake::v256();
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
