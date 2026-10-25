//! Deterministic ML-DSA-65 test corpora (valid and corrupted signatures) and the RustCrypto
//! `ml-dsa` 0.1.1 oracle. Used by the tests and the `bench` binary.
//!
//! Corruptions are adapted from `canggu-gpu/tests/differential.rs`.

use ml_dsa::{
	signature::Keypair, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};
use std::sync::OnceLock;

/// The chain's transaction context string.
pub const CTX: &[u8] = b"canggu/tx/v1";

const PK_LEN: usize = 1952;
const SIG_LEN: usize = 3309;
const CTILDE: usize = 48;
const Z_LEN: usize = 3200;
const HINT: usize = CTILDE + Z_LEN;
const OMEGA: usize = 55;
const K: usize = 6;
const GAMMA1: u32 = 1 << 19;
const BETA: u32 = 196;

/// Number of distinct deterministic keys.
pub const NUM_KEYS: usize = 64;

/// SplitMix64: tiny deterministic PRNG so corpora are reproducible without extra dependencies.
pub struct Rng(pub u64);

impl Rng {
	/// Next 64 random bits.
	pub fn next_u64(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
		z ^ (z >> 31)
	}

	/// Uniform-ish in `0..n`.
	pub fn below(&mut self, n: usize) -> usize {
		(self.next_u64() % n as u64) as usize
	}

	/// `len` random bytes.
	pub fn bytes(&mut self, len: usize) -> Vec<u8> {
		(0..len).map(|_| self.next_u64() as u8).collect()
	}
}

/// One test vector.
#[derive(Clone, Debug)]
pub struct Case {
	/// What kind of corruption (or `"valid"`).
	pub category: &'static str,
	/// Encoded public key.
	pub public: Vec<u8>,
	/// Message.
	pub msg: Vec<u8>,
	/// Encoded signature.
	pub signature: Vec<u8>,
}

impl Case {
	/// As a `(pk, msg, sig)` item for the prover API.
	pub fn item(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
		(self.public.clone(), self.msg.clone(), self.signature.clone())
	}
}

struct Key {
	sk: SigningKey<MlDsa65>,
	pk: Vec<u8>,
}

fn keys() -> &'static [Key] {
	static KEYS: OnceLock<Vec<Key>> = OnceLock::new();
	KEYS.get_or_init(|| {
		let mut rng = Rng(1);
		(0..NUM_KEYS)
			.map(|_| {
				let mut seed = [0u8; 32];
				seed.copy_from_slice(&rng.bytes(32));
				let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
				let pk = sk.verifying_key().encode().to_vec();
				Key { sk, pk }
			})
			.collect()
	})
}

/// The encoded public key of deterministic key `i % NUM_KEYS`.
pub fn public_key(i: usize) -> Vec<u8> {
	keys()[i % NUM_KEYS].pk.clone()
}

/// Deterministic signature (FIPS 204 hedged variant with `rnd = 0`) by key `i % NUM_KEYS`.
pub fn sign(i: usize, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
	keys()[i % NUM_KEYS]
		.sk
		.expanded_key()
		.sign_deterministic(msg, ctx)
		.expect("ctx <= 255")
		.encode()
		.to_vec()
}

/// `n` valid signatures under `ctx` from many keys with message lengths spread over 0..1000.
pub fn valid_cases(n: usize, ctx: &[u8], seed: u64) -> Vec<Case> {
	let mut rng = Rng(seed);
	(0..n)
		.map(|i| {
			let key = (i * 7 + seed as usize) % NUM_KEYS;
			let len = match i % 50 {
				0 => 0,
				1 => 999,
				_ => rng.below(1000),
			};
			let msg = rng.bytes(len);
			let signature = sign(key, &msg, ctx);
			Case { category: "valid", public: public_key(key), msg, signature }
		})
		.collect()
}

/// `n` valid signatures over chain-like intent messages (~100 bytes), as the benchmarks use.
pub fn intent_items(n: usize, ctx: &[u8]) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
	(0..n)
		.map(|i| {
			let mut msg = b"canggu/intent/v1".to_vec();
			msg.extend_from_slice(&(i as u64).to_le_bytes());
			msg.extend_from_slice(&[0x5A; 76]);
			let sig = sign(i, &msg, ctx);
			(public_key(i), msg, sig)
		})
		.collect()
}

fn flip_bit(bytes: &mut [u8], bit: usize) {
	bytes[bit / 8] ^= 1 << (bit % 8);
}

/// Overwrite the 20-bit z field number `m` (0 .. 5 * 256) with `v`.
fn set_z_field(sig: &mut [u8], m: usize, v: u32) {
	let z = &mut sig[CTILDE..HINT];
	for b in 0..20 {
		let bit = m * 20 + b;
		let mask = 1u8 << (bit % 8);
		if (v >> b) & 1 == 1 {
			z[bit / 8] |= mask;
		} else {
			z[bit / 8] &= !mask;
		}
	}
}

/// `n` corrupted variants of `valid` (round-robin over all categories), each of which must be
/// rejected by a correct verifier under the context the valid cases were signed with.
pub fn invalid_cases(valid: &[Case], n: usize, rng: &mut Rng) -> Vec<Case> {
	let mut out = Vec::with_capacity(n);
	let mut variant = 0usize;
	while out.len() < n {
		let mut c = valid[rng.below(valid.len())].clone();
		variant += 1;
		let category = match variant % 17 {
			0 => {
				flip_bit(&mut c.signature, rng.below(CTILDE * 8));
				"sig bit flip: c~"
			},
			1 => {
				flip_bit(&mut c.signature, CTILDE * 8 + rng.below(Z_LEN * 8));
				"sig bit flip: z"
			},
			2 => {
				flip_bit(&mut c.signature, HINT * 8 + rng.below((OMEGA + K) * 8));
				"sig bit flip: hint"
			},
			3 => {
				flip_bit(&mut c.public, rng.below(32 * 8));
				"pk bit flip: rho"
			},
			4 => {
				flip_bit(&mut c.public, 32 * 8 + rng.below((PK_LEN - 32) * 8));
				"pk bit flip: t1"
			},
			5 => {
				if c.msg.is_empty() {
					c.msg.push(rng.next_u64() as u8);
				} else {
					let bit = rng.below(c.msg.len() * 8);
					flip_bit(&mut c.msg, bit);
				}
				"msg bit flip"
			},
			6 => {
				c.msg.push(0);
				"msg extended"
			},
			7 => {
				match rng.below(6) {
					0 => c.signature.truncate(SIG_LEN - 1),
					1 => c.signature.push(0),
					2 => c.public.truncate(PK_LEN - 1),
					3 => c.public.push(0),
					4 => c.signature.clear(),
					_ => c.public.clear(),
				}
				"wrong length"
			},
			8 => {
				let y = &mut c.signature[HINT..HINT + OMEGA + K];
				y[OMEGA + rng.below(K)] = (OMEGA + 1 + rng.below(200)) as u8;
				"hint: cut > omega"
			},
			9 => {
				let y = &mut c.signature[HINT..HINT + OMEGA + K];
				let i = 1 + rng.below(K - 1);
				if y[OMEGA + i - 1] == 0 {
					y[OMEGA + i - 1] = 1;
				}
				y[OMEGA + i] = y[OMEGA + i - 1] - 1;
				"hint: decreasing cuts"
			},
			10 => {
				let y = &mut c.signature[HINT..HINT + OMEGA + K];
				let total = y[OMEGA + K - 1] as usize;
				if total >= OMEGA {
					continue;
				}
				y[total + rng.below(OMEGA - total)] = 1 + rng.below(255) as u8;
				"hint: non-zero padding"
			},
			11 => {
				// Well-formed but different hint: drop the last hint bit of the last non-empty
				// polynomial.
				let y = &mut c.signature[HINT..HINT + OMEGA + K];
				let total = y[OMEGA + K - 1] as usize;
				if total == 0 {
					continue;
				}
				y[total - 1] = 0;
				let i = (0..K).find(|&i| y[OMEGA + i] as usize == total).expect("a cut");
				for cut in &mut y[OMEGA + i..] {
					*cut -= 1;
				}
				"hint: valid encoding, wrong hint"
			},
			12 => {
				let m = rng.below(5 * 256);
				let v = match rng.below(4) {
					0 => 0,
					1 => BETA,
					2 => 2 * GAMMA1 - BETA,
					_ => rng.below(BETA as usize) as u32,
				};
				set_z_field(&mut c.signature, m, v);
				"z out of range"
			},
			13 => {
				set_z_field(&mut c.signature, rng.below(5 * 256), BETA + 1);
				"z at the bound edge (forged)"
			},
			14 => {
				c.signature = rng.bytes(SIG_LEN);
				"random signature bytes"
			},
			15 => {
				let other = &valid[rng.below(valid.len())];
				if other.msg == c.msg {
					continue;
				}
				c.signature = other.signature.clone();
				"signature from other message"
			},
			_ => {
				let other = public_key(rng.below(NUM_KEYS));
				if other == c.public {
					continue;
				}
				c.public = other;
				"public key of other signer"
			},
		};
		c.category = category;
		out.push(c);
	}
	out
}

/// RustCrypto `ml-dsa` 0.1.1 as the oracle (wrong-length inputs are rejected).
pub fn ml_dsa_verify(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
	let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else {
		return false;
	};
	let vk = VerifyingKey::<MlDsa65>::decode(&enc);
	let Ok(sig) = Signature::<MlDsa65>::try_from(sig) else {
		return false;
	};
	vk.verify_with_context(msg, ctx, &sig)
}
