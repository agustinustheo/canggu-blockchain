//! Arithmetic in Z_q and the number-theoretic transform over Z_q[X]/(X^256 + 1).
//!
//! Every function here has a line-by-line twin in `shaders/verify.metal`. All values that cross
//! function boundaries are fully reduced to `[0, q)`, so intermediate representations never
//! leak into results: any correct implementation of these maps produces identical bits.
//!
//! Multiplication uses 32-bit Montgomery reduction (R = 2^32) built only from 32-bit
//! multiply-low / multiply-high operations, which the GPU executes natively.

use crate::params::{N, Q};

/// -q^{-1} mod 2^32.
pub(crate) const NEG_QINV: u32 = {
	// Newton iteration for the inverse of an odd number modulo 2^32.
	let mut inv: u32 = Q;
	let mut i = 0;
	while i < 5 {
		inv = inv.wrapping_mul(2u32.wrapping_sub(Q.wrapping_mul(inv)));
		i += 1;
	}
	inv.wrapping_neg()
};

/// 2^64 mod q, used to move a value into the Montgomery domain.
pub(crate) const R2: u32 = ((1u128 << 64) % Q as u128) as u32;

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

/// `ZETAS_MONT[k] = 1753^{BitRev8(k)} * 2^32 mod q` (FIPS 204, Appendix B, Montgomery form).
pub(crate) const ZETAS_MONT: [u32; N] = {
	let mut t = [0u32; N];
	let mut k = 0;
	while k < N {
		let brv = (k as u8).reverse_bits() as u64;
		let z = pow_mod(ZETA, brv);
		t[k] = ((z << 32) % Q as u64) as u32;
		k += 1;
	}
	t
};

/// `256^{-1} * 2^32 mod q`: Montgomery-multiplying by this scales by 1/256.
pub(crate) const INV_N_MONT: u32 = ((pow_mod(N as u64, Q as u64 - 2) << 32) % Q as u64) as u32;

/// High 32 bits of the 64-bit product (MSL `mulhi`).
#[inline(always)]
fn mulhi(a: u32, b: u32) -> u32 {
	((u64::from(a) * u64::from(b)) >> 32) as u32
}

/// Montgomery multiplication: returns `a * b * 2^-32 mod q` in `[0, q)` for `a, b < q`.
#[inline(always)]
pub(crate) fn mont_mul(a: u32, b: u32) -> u32 {
	let lo = a.wrapping_mul(b);
	let hi = mulhi(a, b);
	let m = lo.wrapping_mul(NEG_QINV);
	// a*b + m*q is divisible by 2^32; its low words sum to 0 or exactly 2^32.
	let t = hi + mulhi(m, Q) + u32::from(lo != 0);
	if t >= Q {
		t - Q
	} else {
		t
	}
}

/// `a + b mod q` for `a, b < q`.
#[inline(always)]
pub(crate) fn add_mod(a: u32, b: u32) -> u32 {
	let t = a + b;
	if t >= Q {
		t - Q
	} else {
		t
	}
}

/// `a - b mod q` for `a, b < q`.
#[inline(always)]
pub(crate) fn sub_mod(a: u32, b: u32) -> u32 {
	add_mod(a, Q - b)
}

/// Convert to Montgomery form (`a * 2^32 mod q`), so that a later `mont_mul` with a plain value
/// yields a plain product.
#[inline(always)]
pub(crate) fn to_mont(a: u32) -> u32 {
	mont_mul(a, R2)
}

/// Forward NTT (FIPS 204 Algorithm 41), in place; output in bit-reversed order.
///
/// Written as "layer by layer, butterfly index `t` in 0..128" exactly like the cooperative
/// threadgroup version on the GPU, where `t` is the thread index.
pub(crate) fn ntt(a: &mut [u32; N]) {
	let mut len = 128;
	while len > 0 {
		for t in 0..N / 2 {
			let group = t / len;
			let j = 2 * len * group + t % len;
			let zeta = ZETAS_MONT[N / (2 * len) + group];
			let u = a[j];
			let v = mont_mul(zeta, a[j + len]);
			a[j] = add_mod(u, v);
			a[j + len] = sub_mod(u, v);
		}
		len >>= 1;
	}
}

/// Inverse NTT (FIPS 204 Algorithm 42), in place; input in bit-reversed order.
pub(crate) fn inv_ntt(a: &mut [u32; N]) {
	let mut len = 1;
	while len < N {
		for t in 0..N / 2 {
			let group = t / len;
			let j = 2 * len * group + t % len;
			let zeta = Q - ZETAS_MONT[N / len - 1 - group];
			let u = a[j];
			let v = a[j + len];
			a[j] = add_mod(u, v);
			a[j + len] = mont_mul(zeta, sub_mod(u, v));
		}
		len <<= 1;
	}
	for x in a.iter_mut() {
		*x = mont_mul(*x, INV_N_MONT);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn constants() {
		assert_eq!(Q.wrapping_mul(NEG_QINV.wrapping_neg()), 1);
		assert_eq!(ZETAS_MONT[0], ((1u64 << 32) % Q as u64) as u32);
		// zeta^256 = -1 mod q.
		assert_eq!(pow_mod(ZETA, 256), Q as u64 - 1);
	}

	#[test]
	fn mont_mul_matches_naive() {
		let rinv = pow_mod((1u64 << 32) % Q as u64, Q as u64 - 2);
		let mut x = 12345u64;
		for _ in 0..100_000 {
			x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			let a = ((x >> 7) % Q as u64) as u32;
			let b = ((x >> 33) % Q as u64) as u32;
			let want = u64::from(a) * u64::from(b) % Q as u64 * rinv % Q as u64;
			assert_eq!(u64::from(mont_mul(a, b)), want);
		}
		for (a, b) in [(0, 0), (Q - 1, Q - 1), (Q - 1, 1), (1, 0), (0, Q - 1)] {
			let want = u64::from(a) * u64::from(b) % Q as u64 * rinv % Q as u64;
			assert_eq!(u64::from(mont_mul(a, b)), want);
		}
	}

	#[test]
	#[allow(clippy::needless_range_loop)] // Index-based maths reads closer to the definition.
	fn ntt_multiplication_matches_schoolbook() {
		let mut a = [0u32; N];
		let mut b = [0u32; N];
		let mut x = 99u64;
		for i in 0..N {
			x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			a[i] = ((x >> 11) % Q as u64) as u32;
			b[i] = ((x >> 37) % Q as u64) as u32;
		}
		// Negacyclic schoolbook product.
		let mut want = [0u64; N];
		for i in 0..N {
			for j in 0..N {
				let p = u64::from(a[i]) * u64::from(b[j]) % Q as u64;
				let k = (i + j) % N;
				if i + j < N {
					want[k] = (want[k] + p) % Q as u64;
				} else {
					want[k] = (want[k] + Q as u64 - p) % Q as u64;
				}
			}
		}
		let (mut ah, mut bh) = (a, b);
		ntt(&mut ah);
		ntt(&mut bh);
		let mut c = [0u32; N];
		for i in 0..N {
			c[i] = mont_mul(ah[i], to_mont(bh[i]));
		}
		inv_ntt(&mut c);
		for i in 0..N {
			assert_eq!(u64::from(c[i]), want[i]);
		}
		// Round trip.
		let mut r = a;
		ntt(&mut r);
		inv_ntt(&mut r);
		assert_eq!(r, a);
	}
}
