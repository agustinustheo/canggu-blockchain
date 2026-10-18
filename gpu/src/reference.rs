//! Pure-Rust execution of the lattice stage, one function per GPU kernel.
//!
//! Each `kernel_*` function below computes exactly what one GPU thread (or threadgroup) computes
//! in the kernel of the same name in `shaders/verify.metal`, reading the same job record and
//! producing the same intermediate buffers. Running the four in order over every job is
//! FIPS 204 Algorithm 8 (`ML-DSA.Verify_internal`) for ML-DSA-65.

use crate::{
	arith::{add_mod, inv_ntt, mont_mul, ntt, sub_mod, to_mont},
	keccak::{keccak_f1600, Shake, SHAKE128_RATE},
	params::{
		CTILDE_BYTES, D, GAMMA2, K, L, N, Q, T1_POLY_BYTES, W1_BYTES, W1_POLY_BYTES, Z_POLY_BYTES,
	},
	prepare::{
		unpack_bits, z_from_field, JOB_C, JOB_CTILDE, JOB_HINT, JOB_MU, JOB_PK, JOB_VALID, JOB_Z,
	},
};

type Poly = [u32; N];

/// Intermediate buffers of one job, mirroring the GPU scratch buffers.
pub(crate) struct Scratch {
	/// `NTT(z_j)` in Montgomery form.
	z_hat: [Poly; L],
	/// `NTT(t1_i * 2^d)`.
	t1_hat: [Poly; K],
	/// `NTT(c)` in Montgomery form.
	c_hat: Poly,
	/// `A_hat[i][j] o z_hat[j]`.
	prod: [[Poly; L]; K],
	/// `w1Encode(UseHint(h, w'_approx))`.
	w1: [u8; W1_BYTES],
}

impl Scratch {
	pub(crate) fn new() -> Box<Self> {
		Box::new(Scratch {
			z_hat: [[0; N]; L],
			t1_hat: [[0; N]; K],
			c_hat: [0; N],
			prod: [[[0; N]; L]; K],
			w1: [0; W1_BYTES],
		})
	}
}

/// Kernel 1 (`ntt_inputs`), one threadgroup per `(job, p)` with `p < L + K + 1`: unpack and
/// transform `z_p`, `t1_{p-L} * 2^d` or `c` into the NTT domain.
pub(crate) fn kernel_ntt_inputs(job: &[u8], p: usize, s: &mut Scratch) {
	let mut a = [0u32; N];
	for (m, x) in a.iter_mut().enumerate() {
		*x = if p < L {
			z_from_field(unpack_bits(&job[JOB_Z + p * Z_POLY_BYTES..], m, 20))
		} else if p < L + K {
			let t1 = &job[JOB_PK + 32 + (p - L) * T1_POLY_BYTES..];
			// t1 < 2^10, so t1 * 2^13 <= q - 1 is already reduced.
			unpack_bits(t1, m, 10) << D
		} else {
			match job[JOB_C + m] {
				0 => 0,
				1 => 1,
				_ => Q - 1,
			}
		};
	}
	ntt(&mut a);
	if p < L {
		s.z_hat[p] = a.map(to_mont);
	} else if p < L + K {
		s.t1_hat[p - L] = a;
	} else {
		s.c_hat = a.map(to_mont);
	}
}

/// Kernel 2 (`expand_a`), one thread per `(job, i, j)`: sample `A_hat[i][j]` with
/// `RejNTTPoly(rho || j || i)` (FIPS 204 Algorithms 30 and 32) and multiply it pointwise by
/// `z_hat[j]`.
pub(crate) fn kernel_expand_a(job: &[u8], i: usize, j: usize, s: &mut Scratch) {
	// Absorb rho || j || i directly into the SHAKE128 state, then pad.
	let mut st = [0u64; 25];
	for w in 0..4 {
		let b = &job[JOB_PK + 8 * w..JOB_PK + 8 * w + 8];
		st[w] = u64::from_le_bytes(b.try_into().expect("8 bytes"));
	}
	st[4] = j as u64 | (i as u64) << 8 | 0x1F << 16;
	st[SHAKE128_RATE / 8 - 1] ^= 0x80 << 56;

	let out = &mut s.prod[i][j];
	let zj = &s.z_hat[j];
	let mut m = 0;
	while m < N {
		keccak_f1600(&mut st);
		let byte = |k: usize| (st[k / 8] >> (8 * (k % 8))) as u32 & 0xFF;
		let mut k = 0;
		while k < SHAKE128_RATE && m < N {
			// CoeffFromThreeBytes: clear the top bit of the third byte, accept if < q.
			let a = byte(k) | byte(k + 1) << 8 | (byte(k + 2) & 0x7F) << 16;
			if a < Q {
				out[m] = mont_mul(a, zj[m]);
				m += 1;
			}
			k += 3;
		}
	}
}

/// FIPS 204 Algorithm 40 `UseHint` (with Algorithm 36 `Decompose`) for 2*gamma2 = (q-1)/16.
pub(crate) fn use_hint(h: bool, r: u32) -> u32 {
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

/// Kernel 3 (`rows`), one threadgroup per `(job, i)`:
/// `w1_i = UseHint(h_i, NTT^-1(sum_j prod[i][j] - c_hat o t1_hat_i))`, then `w1Encode`.
pub(crate) fn kernel_rows(job: &[u8], i: usize, s: &mut Scratch) {
	let mut w = [0u32; N];
	for (m, x) in w.iter_mut().enumerate() {
		let mut acc = 0;
		for j in 0..L {
			acc = add_mod(acc, s.prod[i][j][m]);
		}
		*x = sub_mod(acc, mont_mul(s.c_hat[m], s.t1_hat[i][m]));
	}
	inv_ntt(&mut w);
	let hint = &job[JOB_HINT + i * N / 8..];
	let out = &mut s.w1[i * W1_POLY_BYTES..(i + 1) * W1_POLY_BYTES];
	for (t, o) in out.iter_mut().enumerate() {
		let h = |m: usize| (hint[m / 8] >> (m % 8)) & 1 == 1;
		let lo = use_hint(h(2 * t), w[2 * t]);
		let hi = use_hint(h(2 * t + 1), w[2 * t + 1]);
		*o = (lo | hi << 4) as u8;
	}
}

/// Kernel 4 (`challenge`), one thread per job: `c~' = H(mu || w1Encode(w1'), 48) == c~`.
pub(crate) fn kernel_challenge(job: &[u8], s: &Scratch) -> bool {
	let mut c = [0u8; CTILDE_BYTES];
	let mut h = Shake::v256();
	h.absorb(&job[JOB_MU..JOB_MU + 64]).absorb(&s.w1);
	h.squeeze(&mut c);
	c[..] == job[JOB_CTILDE..JOB_CTILDE + CTILDE_BYTES]
}

/// Run the full lattice stage over one prepared job record.
pub(crate) fn run_job(job: &[u8], s: &mut Scratch) -> bool {
	if job[JOB_VALID] == 0 {
		return false;
	}
	for p in 0..L + K + 1 {
		kernel_ntt_inputs(job, p, s);
	}
	for i in 0..K {
		for j in 0..L {
			kernel_expand_a(job, i, j, s);
		}
	}
	for i in 0..K {
		kernel_rows(job, i, s);
	}
	kernel_challenge(job, s)
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
			// Decompose, written with the mathematical mod+- directly.
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
}
