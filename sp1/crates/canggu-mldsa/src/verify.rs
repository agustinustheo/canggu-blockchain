//! FIPS 204 Algorithm 3 `ML-DSA.Verify` (with Algorithm 8 `Verify_internal`) for ML-DSA-65.
//!
//! Same maths as the `prepare` + `reference` modules of `canggu/gpu`, restructured as one
//! straight-line function with a small working set (the products `A_hat[i][j] o z_hat[j]` are
//! accumulated row by row instead of being stored), which is what matters inside a zkVM.
//!
//! Returns exactly what RustCrypto `ml-dsa` 0.1.1 returns for
//! `Signature::decode(sig).map_or(false, |s| VerifyingKey::decode(pk).verify_with_context(msg,
//! ctx, &s))` (with wrong-length inputs rejected); see `tests/differential.rs`.

use crate::{
	arith::{caddq, inv_ntt_tomont, ntt, pointwise, reduce32},
	keccak::{keccak_f1600, Sponge, SHAKE128_RATE},
	params::{
		BETA, CTILDE_BYTES, D, GAMMA1, GAMMA2, K, L, N, OMEGA, PUBLIC_KEY_BYTES, Q,
		SIGNATURE_BYTES, T1_POLY_BYTES, TAU, W1_BYTES, W1_POLY_BYTES, Z_POLY_BYTES,
	},
};

type Poly = [i32; N];

/// Offset of the hint section inside an encoded signature.
const SIG_HINT: usize = CTILDE_BYTES + L * Z_POLY_BYTES;

/// Verify an ML-DSA-65 signature `sig` on `msg` under `pk` with context string `ctx`.
///
/// Never panics; malformed inputs of any length are rejected.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
	if ctx.len() > 255 || pk.len() != PUBLIC_KEY_BYTES || sig.len() != SIGNATURE_BYTES {
		return false;
	}
	let ctilde = &sig[..CTILDE_BYTES];
	let z_bytes = &sig[CTILDE_BYTES..SIG_HINT];

	// sigDecode: hint first (cheapest to reject), then decode z and check its norm.
	let mut hint = [0u8; K * N / 8];
	if !hint_bit_unpack(&sig[SIG_HINT..], &mut hint) {
		return false;
	}
	let mut z_hat = [[0i32; N]; L];
	for (j, zj) in z_hat.iter_mut().enumerate() {
		if !decode_z(&z_bytes[j * Z_POLY_BYTES..(j + 1) * Z_POLY_BYTES], zj) {
			return false;
		}
		// |z| < gamma1, so |NTT(z)| < gamma1 + 8q.
		ntt(zj);
	}

	// mu = H(H(pk, 64) || 0 || |ctx| || ctx || M, 64).
	let mut tr = [0u8; 64];
	Sponge::shake256().absorb(pk).squeeze(&mut tr);
	let mut mu = [0u8; 64];
	Sponge::shake256()
		.absorb(&tr)
		.absorb(&[0, ctx.len() as u8])
		.absorb(ctx)
		.absorb(msg)
		.squeeze(&mut mu);

	// c_hat = NTT(SampleInBall(c~)), |c_hat| <= 9q.
	let mut c_hat = sample_in_ball(ctilde);
	ntt(&mut c_hat);

	let rho: &[u8; 32] = pk[..32].try_into().expect("32 bytes");
	let mut w1 = [0u8; W1_BYTES];
	for i in 0..K {
		// w_i = NTT^-1( sum_j A_hat[i][j] o z_hat[j] - c_hat o NTT(t1_i * 2^d) ).
		// Every pointwise product is a Montgomery product (factor 2^-32, |.| < q), which
		// `inv_ntt_tomont` cancels. The accumulator stays below (L + 1) q in absolute value.
		let mut acc = [0i32; N];
		for (j, zj) in z_hat.iter().enumerate() {
			expand_a_mul_acc(rho, i, j, zj, &mut acc);
		}
		let mut t1 = decode_t1_shifted(&pk[32 + i * T1_POLY_BYTES..32 + (i + 1) * T1_POLY_BYTES]);
		ntt(&mut t1);
		for ((w, c), t) in acc.iter_mut().zip(c_hat.iter()).zip(t1.iter()) {
			*w = reduce32(*w - pointwise(*c, *t));
		}
		inv_ntt_tomont(&mut acc);
		// The one and only full reduction: canonical representatives in [0, q) for UseHint.
		for w in acc.iter_mut() {
			*w = caddq(*w);
		}

		// w1Encode(UseHint(h_i, w_i)): two 4-bit values per byte.
		let h = &hint[i * N / 8..(i + 1) * N / 8];
		let out = &mut w1[i * W1_POLY_BYTES..(i + 1) * W1_POLY_BYTES];
		for (t, o) in out.iter_mut().enumerate() {
			let bit = |m: usize| (h[m / 8] >> (m % 8)) & 1 == 1;
			let lo = use_hint(bit(2 * t), acc[2 * t] as u32);
			let hi = use_hint(bit(2 * t + 1), acc[2 * t + 1] as u32);
			*o = (lo | hi << 4) as u8;
		}
	}

	// c~' = H(mu || w1Encode(w1'), 48) must equal c~.
	let mut c2 = [0u8; CTILDE_BYTES];
	Sponge::shake256().absorb(&mu).absorb(&w1).squeeze(&mut c2);
	c2[..] == *ctilde
}

/// Decode one packed `z` polynomial (20-bit fields `v`, coefficient `z = gamma1 - v`, so
/// `-gamma1 < z <= gamma1`). Returns `false` if some coefficient has `|z| >= gamma1 - beta`.
fn decode_z(bytes: &[u8], out: &mut Poly) -> bool {
	let bound = (GAMMA1 - BETA) as i32;
	let mut ok = true;
	for (o, b) in out.chunks_exact_mut(2).zip(bytes.chunks_exact(5)) {
		let [b0, b1, b2, b3, b4] = [b[0], b[1], b[2], b[3], b[4]].map(i32::from);
		let z0 = GAMMA1 as i32 - (b0 | b1 << 8 | (b2 & 0xF) << 16);
		let z1 = GAMMA1 as i32 - (b2 >> 4 | b3 << 4 | b4 << 12);
		ok &= z0.abs() < bound && z1.abs() < bound;
		o[0] = z0;
		o[1] = z1;
	}
	ok
}

/// Decode one packed `t1` polynomial (10-bit fields) and multiply by `2^d`. Since `t1 < 2^10`,
/// `t1 * 2^13 <= q - 1` is already reduced.
fn decode_t1_shifted(bytes: &[u8]) -> Poly {
	let mut out = [0i32; N];
	for (o, b) in out.chunks_exact_mut(4).zip(bytes.chunks_exact(5)) {
		let [b0, b1, b2, b3, b4] = [b[0], b[1], b[2], b[3], b[4]].map(i32::from);
		o[0] = (b0 | (b1 & 0x03) << 8) << D;
		o[1] = (b1 >> 2 | (b2 & 0x0F) << 6) << D;
		o[2] = (b2 >> 4 | (b3 & 0x3F) << 4) << D;
		o[3] = (b3 >> 6 | b4 << 2) << D;
	}
	out
}

/// FIPS 204 Algorithm 21 `HintBitUnpack` into a bitmask (bit `m % 8` of byte `32 * i + m / 8` is
/// `h[i][m]`). Returns `false` for any malformed encoding.
fn hint_bit_unpack(y: &[u8], out: &mut [u8; K * N / 8]) -> bool {
	debug_assert_eq!(y.len(), OMEGA + K);
	let mut index = 0usize;
	for i in 0..K {
		let end = usize::from(y[OMEGA + i]);
		if end < index || end > OMEGA {
			return false;
		}
		let first = index;
		while index < end {
			if index > first && y[index - 1] >= y[index] {
				return false;
			}
			let m = usize::from(y[index]);
			out[i * N / 8 + m / 8] |= 1 << (m % 8);
			index += 1;
		}
	}
	y[index..OMEGA].iter().all(|&b| b == 0)
}

/// FIPS 204 Algorithm 29 `SampleInBall`, with coefficients in `{-1, 0, 1}`.
fn sample_in_ball(ctilde: &[u8]) -> Poly {
	let mut c = [0i32; N];
	let mut h = Sponge::shake256();
	h.absorb(ctilde);
	let mut s = [0u8; 8];
	h.squeeze(&mut s);
	let signs = u64::from_le_bytes(s);
	for i in (N - TAU)..N {
		let mut j = usize::from(h.squeeze_byte());
		while j > i {
			j = usize::from(h.squeeze_byte());
		}
		c[i] = c[j];
		let bit = (signs >> (i + TAU - N)) & 1;
		c[j] = 1 - 2 * bit as i32;
	}
	c
}

/// `acc += A o z_hat[j]` (Montgomery products, each `|.| < q`) for `A = A_hat[i][j] = RejNTTPoly(
/// rho || j || i)` (FIPS 204 Algorithms 30, 32), sampled on the fly with SHAKE128, never stored.
fn expand_a_mul_acc(rho: &[u8; 32], i: usize, j: usize, zj: &Poly, acc: &mut Poly) {
	// Absorb rho || j || i (34 bytes, less than one block) directly into the state, then pad.
	let mut st = [0u64; 25];
	for (w, lane) in st.iter_mut().take(4).enumerate() {
		*lane = u64::from_le_bytes(rho[8 * w..8 * w + 8].try_into().expect("8 bytes"));
	}
	st[4] = j as u64 | (i as u64) << 8 | 0x1F << 16;
	st[SHAKE128_RATE / 8 - 1] ^= 0x80 << 56;

	let mut block = [0u8; SHAKE128_RATE];
	let mut m = 0;
	while m < N {
		keccak_f1600(&mut st);
		for (b, lane) in block.chunks_exact_mut(8).zip(st.iter()) {
			b.copy_from_slice(&lane.to_le_bytes());
		}
		for t in block.chunks_exact(3) {
			// CoeffFromThreeBytes: clear the top bit of the third byte, accept if < q.
			let a = u32::from(t[0]) | u32::from(t[1]) << 8 | (u32::from(t[2]) & 0x7F) << 16;
			if a < Q {
				acc[m] += pointwise(a as i32, zj[m]);
				m += 1;
				if m == N {
					break;
				}
			}
		}
	}
}

/// FIPS 204 Algorithm 40 `UseHint` (with Algorithm 36 `Decompose`) for 2*gamma2 = (q-1)/16.
fn use_hint(h: bool, r: u32) -> u32 {
	let two_gamma2 = 2 * GAMMA2;
	let mut r0 = (r % two_gamma2) as i32;
	if r0 > GAMMA2 as i32 {
		r0 -= two_gamma2 as i32;
	}
	let diff = r as i32 - r0;
	let r1 = if diff == (Q - 1) as i32 {
		r0 -= 1;
		0
	} else {
		diff as u32 / two_gamma2
	};
	match (h, r0 > 0) {
		(false, _) => r1,
		(true, true) => (r1 + 1) & 15,
		(true, false) => (r1 + 15) & 15,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Brute-force check of `use_hint` against the literal FIPS 204 definitions.
	#[test]
	fn use_hint_matches_definition() {
		let alpha = 2 * GAMMA2 as i64;
		let m = (Q as i64 - 1) / alpha;
		for r in (0..Q).step_by(97).chain(Q - 300..Q).chain(0..300) {
			let rp = r as i64;
			let mut r0 = rp.rem_euclid(alpha);
			if r0 > alpha / 2 {
				r0 -= alpha;
			}
			let (r1, r0) =
				if rp - r0 == Q as i64 - 1 { (0, r0 - 1) } else { ((rp - r0) / alpha, r0) };
			assert_eq!(use_hint(false, r) as i64, r1);
			let want = if r0 > 0 { (r1 + 1).rem_euclid(m) } else { (r1 - 1).rem_euclid(m) };
			assert_eq!(use_hint(true, r) as i64, want, "r = {r}");
		}
	}

	#[test]
	fn t1_decode_matches_generic_unpack() {
		let bytes: [u8; T1_POLY_BYTES] = core::array::from_fn(|i| (i * 131 + 7) as u8);
		let got = decode_t1_shifted(&bytes);
		for (m, &g) in got.iter().enumerate() {
			let bit = m * 10;
			let word = u32::from(bytes[bit / 8]) | u32::from(bytes[bit / 8 + 1]) << 8;
			assert_eq!(g as u32, ((word >> (bit % 8)) & 0x3FF) << D);
		}
	}

	#[test]
	fn sample_in_ball_has_tau_nonzero() {
		let c = sample_in_ball(&[7u8; CTILDE_BYTES]);
		assert_eq!(c.iter().filter(|&&x| x != 0).count(), TAU);
		assert!(c.iter().all(|&x| x == 0 || x == 1 || x == -1));
	}
}
