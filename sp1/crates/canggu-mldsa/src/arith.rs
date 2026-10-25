//! Arithmetic in Z_q and the number-theoretic transform over Z_q[X]/(X^256 + 1).
//!
//! Signed, lazily reduced Montgomery arithmetic (R = 2^32) as in the Dilithium/ML-DSA reference
//! implementation (`pq-crystals/dilithium`, `ref/ntt.c`, `ref/reduce.c`): coefficients are `i32`
//! representatives that are only *congruent* to the true value and are kept within proven bounds
//! instead of being reduced after every operation. Inside the zkVM every skipped comparison and
//! conditional subtraction is a saved instruction (cycle); the NTT went from ~25 to ~12 RISC-V
//! instructions per butterfly.
//!
//! The verifier reduces to the canonical representative in `[0, q)` (`caddq(reduce32(..))`)
//! exactly once, before `UseHint`, so the result is bit-for-bit the same as with eager reduction
//! (the GPU/CPU code in `canggu/gpu/src/arith.rs`, which this replaces).
//!
//! Bounds (from the reference implementation):
//! * [`montgomery_reduce`]: for `|a| < 2^31 q`, returns `r = a 2^-32 mod q` with `|r| < q`.
//! * [`ntt`]: input `|a| < 2^31 - 8q`; each layer grows the bound by at most `q`.
//! * [`inv_ntt_tomont`]: input `|a| < q`; output `|a| < q`, multiplied by `2^32` (so a
//!   preceding [`pointwise`] Montgomery product comes out plain).

use crate::params::{N, Q};

const QI: i32 = Q as i32;

/// q^{-1} mod 2^32.
const QINV: i32 = {
	// Newton iteration for the inverse of an odd number modulo 2^32.
	let mut inv: u32 = Q;
	let mut i = 0;
	while i < 5 {
		inv = inv.wrapping_mul(2u32.wrapping_sub(Q.wrapping_mul(inv)));
		i += 1;
	}
	inv as i32
};

/// Primitive 512-th root of unity mod q used by ML-DSA.
const ZETA: u64 = 1753;

const fn pow_mod(mut base: u64, mut exp: u64) -> u64 {
	let mut acc = 1u64;
	base %= Q as u64;
	while exp > 0 {
		if exp & 1 == 1 {
			acc = acc * base % Q as u64;
		}
		base = base * base % Q as u64;
		exp >>= 1;
	}
	acc
}

/// `ZETAS[k] = 1753^{BitRev8(k)} * 2^32 mod q`, centred in `(-q/2, q/2]` (FIPS 204, Appendix
/// B, in Montgomery form). Identical to the reference implementation's `zetas` for `k >= 1`.
pub(crate) const ZETAS: [i32; N] = {
	let mut t = [0i32; N];
	let mut k = 0;
	while k < N {
		let brv = (k as u8).reverse_bits() as u64;
		let z = ((pow_mod(ZETA, brv) << 32) % Q as u64) as i32;
		t[k] = if z > QI / 2 { z - QI } else { z };
		k += 1;
	}
	t
};

/// `2^64 / 256 mod q`: Montgomery-multiplying by this scales by `2^32 / 256`.
const F: i32 = ((pow_mod(N as u64, Q as u64 - 2) << 32) % Q as u64 * ((1u64 << 32) % Q as u64)
	% Q as u64) as i32;

/// Montgomery reduction: for `|a| < 2^31 q`, returns `r = a 2^-32 mod q` with `|r| < q`.
#[inline(always)]
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
	let t = (a as i32).wrapping_mul(QINV);
	((a - i64::from(t) * i64::from(QI)) >> 32) as i32
}

/// For `a <= 2^31 - 2^22 - 1`, returns `r = a mod q` with `-6283008 <= r <= 6283008`.
#[inline(always)]
pub(crate) fn reduce32(a: i32) -> i32 {
	let t = (a + (1 << 22)) >> 23;
	a - t * QI
}

/// Adds `q` if `a` is negative: maps `(-q, q)` to `[0, q)`.
#[inline(always)]
pub(crate) fn caddq(a: i32) -> i32 {
	a + ((a >> 31) & QI)
}

/// Pointwise Montgomery product `a b 2^-32`.
#[inline(always)]
pub(crate) fn pointwise(a: i32, b: i32) -> i32 {
	montgomery_reduce(i64::from(a) * i64::from(b))
}

/// Forward NTT (FIPS 204 Algorithm 41), in place, no reduction; output in bit-reversed order.
pub(crate) fn ntt(a: &mut [i32; N]) {
	let mut k = 0;
	let mut len = 128;
	while len > 0 {
		for block in a.chunks_exact_mut(2 * len) {
			k += 1;
			let zeta = i64::from(ZETAS[k]);
			let (lo, hi) = block.split_at_mut(len);
			for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
				let t = montgomery_reduce(zeta * i64::from(*y));
				*y = *x - t;
				*x += t;
			}
		}
		len >>= 1;
	}
}

/// Inverse NTT (FIPS 204 Algorithm 42), in place, followed by multiplication by `2^32`; input
/// in bit-reversed order. Input `|a| < q`, output `|a| < q`.
pub(crate) fn inv_ntt_tomont(a: &mut [i32; N]) {
	let mut k = N;
	let mut len = 1;
	while len < N {
		for block in a.chunks_exact_mut(2 * len) {
			k -= 1;
			let zeta = -i64::from(ZETAS[k]);
			let (lo, hi) = block.split_at_mut(len);
			for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
				let t = *x;
				*x = t + *y;
				*y = montgomery_reduce(zeta * i64::from(t - *y));
			}
		}
		len <<= 1;
	}
	let f = i64::from(F);
	for x in a.iter_mut() {
		*x = montgomery_reduce(f * i64::from(*x));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const QL: i64 = Q as i64;

	#[test]
	fn constants() {
		assert_eq!(QI.wrapping_mul(QINV), 1);
		// zeta^256 = -1 mod q.
		assert_eq!(pow_mod(ZETA, 256), Q as u64 - 1);
		// A few entries of the reference `zetas` table.
		assert_eq!(ZETAS[1..6], [25847, -2608894, -518909, 237124, -777960]);
		assert_eq!(ZETAS[255], 1976782);
		assert_eq!(F, 41978);
	}

	#[test]
	fn reductions_match_naive() {
		let rinv = pow_mod((1u64 << 32) % Q as u64, Q as u64 - 2) as i64;
		let mut x = 12345u64;
		for i in 0..200_000 {
			x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			// Full allowed input range |a| < 2^31 q, plus edge cases.
			let a = match i {
				0 => (1i64 << 31) * QL - 1,
				1 => -(1i64 << 31) * QL + 1,
				2 => 0,
				_ => (x as i64) % ((1i64 << 31) * QL),
			};
			let r = montgomery_reduce(a);
			assert!(i64::from(r).abs() < QL);
			assert_eq!((i64::from(r) - (a % QL) * rinv).rem_euclid(QL), 0);
			let b = (x >> 33) as i32 & 0x7FBF_FFFF;
			let b = if x & 1 == 1 { -b } else { b };
			let r = reduce32(b);
			assert!(r.abs() <= 6283008);
			assert_eq!((i64::from(r) - i64::from(b)).rem_euclid(QL), 0);
		}
		for a in [-QI + 1, -1, 0, 1, QI - 1] {
			let c = caddq(a);
			assert!((0..QI).contains(&c));
			assert_eq!((c - a).rem_euclid(QI), 0);
		}
	}

	#[test]
	#[allow(clippy::needless_range_loop)] // Index-based maths reads closer to the definition.
	fn ntt_multiplication_matches_schoolbook() {
		let mut x = 99u64;
		for round in 0..4 {
			let mut a = [0i32; N];
			let mut b = [0i32; N];
			for i in 0..N {
				x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
				// Signed inputs like z (|z| < gamma1), t1 * 2^d (< q) and c (|c| <= 1).
				a[i] = match round {
					0 => ((x >> 11) % (2 * (1 << 19)) as u64) as i32 - (1 << 19),
					_ => ((x >> 11) % QL as u64) as i32,
				};
				b[i] = match round {
					1 => ((x >> 37) % 3) as i32 - 1,
					_ => ((x >> 37) % QL as u64) as i32,
				};
			}
			// Negacyclic schoolbook product.
			let mut want = [0i64; N];
			for i in 0..N {
				for j in 0..N {
					let p = i64::from(a[i]) * i64::from(b[j]) % QL;
					let k = (i + j) % N;
					want[k] = if i + j < N { want[k] + p } else { want[k] - p }.rem_euclid(QL);
				}
			}
			let (mut ah, mut bh) = (a, b);
			ntt(&mut ah);
			ntt(&mut bh);
			let mut c = [0i32; N];
			for i in 0..N {
				c[i] = reduce32(pointwise(ah[i], bh[i]));
			}
			inv_ntt_tomont(&mut c);
			for i in 0..N {
				assert!(c[i].abs() < QI);
				assert_eq!(i64::from(caddq(c[i])), want[i], "round {round}, coefficient {i}");
			}
		}
	}
}
