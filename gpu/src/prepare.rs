//! CPU pre-processing: everything that is cheap, variable-length or branchy.
//!
//! For each item this performs the length checks, `sigDecode` validation (hint encoding and the
//! `||z||_inf < gamma1 - beta` bound), computes `tr = H(pk, 64)`,
//! `mu = H(tr || 0 || |ctx| || ctx || M, 64)` and the challenge `c = SampleInBall(c~)`, and lays
//! the result out as a fixed-size [`JOB_BYTES`] record that both the GPU kernels and the
//! pure-Rust reference pipeline consume.
//!
//! The packed `t1` and `z` are copied verbatim and unpacked again by the lattice stage, so the GPU
//! does the decoding of the large vectors itself; the CPU only *validates* `z`.

use crate::{
	keccak::Shake,
	params::{
		BETA, CTILDE_BYTES, GAMMA1, K, L, N, OMEGA, PUBLIC_KEY_BYTES, Q, SIGNATURE_BYTES, TAU,
		Z_POLY_BYTES,
	},
	Item,
};

// Job record layout (byte offsets). Mirrored into the shader via generated `#define`s.

/// Encoded public key `rho || t1` (1952 bytes).
pub(crate) const JOB_PK: usize = 0;
/// Packed `z` exactly as in the signature (3200 bytes).
pub(crate) const JOB_Z: usize = JOB_PK + PUBLIC_KEY_BYTES;
/// Hint as a bitmask: bit `m % 8` of byte `32 * i + m / 8` is `h[i][m]` (192 bytes).
pub(crate) const JOB_HINT: usize = JOB_Z + L * Z_POLY_BYTES;
/// Challenge polynomial `c` as signed bytes in {-1, 0, 1} (256 bytes).
pub(crate) const JOB_C: usize = JOB_HINT + K * N / 8;
/// Message representative `mu` (64 bytes).
pub(crate) const JOB_MU: usize = JOB_C + N;
/// Commitment hash `c~` from the signature (48 bytes).
pub(crate) const JOB_CTILDE: usize = JOB_MU + 64;
/// Non-zero if the item passed all CPU checks and must be evaluated by the lattice stage.
pub(crate) const JOB_VALID: usize = JOB_CTILDE + CTILDE_BYTES;
/// Total record size, padded to a multiple of 32 bytes.
pub(crate) const JOB_BYTES: usize = (JOB_VALID + 1).div_ceil(32) * 32;

const _: () = assert!(JOB_BYTES == 5728);

/// Offset of the hint section inside an encoded signature.
const SIG_HINT: usize = CTILDE_BYTES + L * Z_POLY_BYTES;

/// Read the `w`-bit little-endian field number `m` from `bytes` (FIPS 204 `BitUnpack` core).
///
/// Only touches the bytes that actually contain the field, so it never reads past the end of a
/// packed polynomial.
#[inline(always)]
pub(crate) fn unpack_bits(bytes: &[u8], m: usize, w: usize) -> u32 {
	let bit = m * w;
	let first = bit / 8;
	let last = (bit + w - 1) / 8;
	let mut acc = 0u32;
	for (k, b) in bytes[first..=last].iter().enumerate() {
		acc |= u32::from(*b) << (8 * k);
	}
	(acc >> (bit % 8)) & ((1u32 << w) - 1)
}

/// Map an unpacked 20-bit `z` field `v` to `gamma1 - v mod q`.
#[inline(always)]
pub(crate) fn z_from_field(v: u32) -> u32 {
	let t = GAMMA1 + Q - v;
	if t >= Q {
		t - Q
	} else {
		t
	}
}

/// `|gamma1 - v|`, the infinity norm of a centred `z` coefficient.
#[inline(always)]
fn z_abs(v: u32) -> u32 {
	v.abs_diff(GAMMA1)
}

/// Whether any coefficient of the packed `z` (20-bit fields, two per five bytes) has
/// `|gamma1 - v| >= gamma1 - beta`.
fn z_norm_too_large(z: &[u8]) -> bool {
	debug_assert_eq!(z.len(), L * Z_POLY_BYTES);
	let mut bad = false;
	for b in z.chunks_exact(5) {
		let [b0, b1, b2, b3, b4] = [b[0], b[1], b[2], b[3], b[4]].map(u32::from);
		let v0 = b0 | b1 << 8 | (b2 & 0xF) << 16;
		let v1 = b2 >> 4 | b3 << 4 | b4 << 12;
		bad |= z_abs(v0) >= GAMMA1 - BETA || z_abs(v1) >= GAMMA1 - BETA;
	}
	bad
}

/// FIPS 204 Algorithm 21 `HintBitUnpack`, producing the bitmask layout used in the job record.
/// Returns `None` for any malformed encoding.
fn hint_bit_unpack(y: &[u8], out: &mut [u8]) -> Option<()> {
	debug_assert_eq!(y.len(), OMEGA + K);
	debug_assert_eq!(out.len(), K * N / 8);
	out.fill(0);
	let mut index = 0usize;
	for i in 0..K {
		let end = usize::from(y[OMEGA + i]);
		if end < index || end > OMEGA {
			return None;
		}
		let first = index;
		while index < end {
			if index > first && y[index - 1] >= y[index] {
				return None;
			}
			let m = usize::from(y[index]);
			out[i * N / 8 + m / 8] |= 1 << (m % 8);
			index += 1;
		}
	}
	if y[index..OMEGA].iter().any(|&b| b != 0) {
		return None;
	}
	Some(())
}

/// FIPS 204 Algorithm 29 `SampleInBall`, writing `c` as signed bytes.
fn sample_in_ball(ctilde: &[u8], out: &mut [u8]) {
	debug_assert_eq!(out.len(), N);
	out.fill(0);
	let mut h = Shake::v256();
	h.absorb(ctilde);
	let mut s = [0u8; 8];
	h.squeeze(&mut s);
	let signs = u64::from_le_bytes(s);
	for i in (N - TAU)..N {
		let mut j = usize::from(h.squeeze_byte());
		while j > i {
			j = usize::from(h.squeeze_byte());
		}
		out[i] = out[j];
		let bit = (signs >> (i + TAU - N)) & 1;
		out[j] = if bit == 1 { (-1i8) as u8 } else { 1 };
	}
}

/// Fill `job` for `item`. Returns `false` (and clears the valid flag) if the item is rejected by
/// the CPU checks; in that case the remaining record contents are unspecified and ignored.
pub(crate) fn prepare_job(item: &Item, ctx: &[u8], job: &mut [u8]) -> bool {
	debug_assert_eq!(job.len(), JOB_BYTES);
	job[JOB_VALID] = 0;
	let ok = fill_job(item, ctx, job).is_some();
	job[JOB_VALID] = u8::from(ok);
	ok
}

fn fill_job(item: &Item, ctx: &[u8], job: &mut [u8]) -> Option<()> {
	if ctx.len() > 255 ||
		item.public.len() != PUBLIC_KEY_BYTES ||
		item.signature.len() != SIGNATURE_BYTES
	{
		return None;
	}
	let sig = item.signature;

	// sigDecode: hint first (cheapest to reject), then the z bound.
	hint_bit_unpack(&sig[SIG_HINT..], &mut job[JOB_HINT..JOB_C])?;
	let z = &sig[CTILDE_BYTES..SIG_HINT];
	if z_norm_too_large(z) {
		return None;
	}

	job[JOB_PK..JOB_Z].copy_from_slice(item.public);
	job[JOB_Z..JOB_HINT].copy_from_slice(z);
	job[JOB_CTILDE..JOB_VALID].copy_from_slice(&sig[..CTILDE_BYTES]);
	sample_in_ball(&sig[..CTILDE_BYTES], &mut job[JOB_C..JOB_MU]);

	let mut tr = [0u8; 64];
	Shake::v256().absorb(item.public).squeeze(&mut tr);
	let mut h = Shake::v256();
	h.absorb(&tr).absorb(&[0, ctx.len() as u8]).absorb(ctx).absorb(item.msg);
	h.squeeze(&mut job[JOB_MU..JOB_CTILDE]);
	Some(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unpack_bits_matches_fips_formulas() {
		let bytes: Vec<u8> = (0..640u32).map(|i| (i * 131 + 7) as u8).collect();
		for p in 0..128 {
			let b = &bytes[5 * p..5 * p + 5];
			let c0 = u32::from(b[0]) | u32::from(b[1]) << 8 | (u32::from(b[2]) & 0xF) << 16;
			let c1 = u32::from(b[2]) >> 4 | u32::from(b[3]) << 4 | u32::from(b[4]) << 12;
			assert_eq!(unpack_bits(&bytes, 2 * p, 20), c0);
			assert_eq!(unpack_bits(&bytes, 2 * p + 1, 20), c1);
		}
		for p in 0..64 {
			let b = &bytes[5 * p..5 * p + 5];
			let c3 = u32::from(b[3]) >> 6 | u32::from(b[4]) << 2;
			assert_eq!(unpack_bits(&bytes[..320], 4 * p + 3, 10), c3);
		}
	}

	#[test]
	fn z_norm_check_matches_generic_unpack() {
		let set_field = |z: &mut [u8], m: usize, v: u32| {
			for b in 0..20 {
				let bit = m * 20 + b;
				z[bit / 8] &= !(1 << (bit % 8));
				z[bit / 8] |= (((v >> b) & 1) as u8) << (bit % 8);
			}
		};
		let mut z = vec![0u8; L * Z_POLY_BYTES];
		for m in 0..L * N {
			// v = gamma1 encodes z = 0.
			set_field(&mut z, m, GAMMA1);
		}
		assert!(!z_norm_too_large(&z));
		let edge = [0, 1, BETA - 1, BETA, BETA + 1, 2 * GAMMA1 - BETA - 1, 2 * GAMMA1 - BETA];
		let mut x = 1u32;
		for m in 0..L * N {
			x = x.wrapping_mul(1664525).wrapping_add(1013904223);
			let v = if m % 3 == 0 { edge[m % edge.len()] } else { x >> 12 };
			let mut zz = z.clone();
			set_field(&mut zz, m, v);
			let generic = (0..L * N).any(|k| z_abs(unpack_bits(&zz, k, 20)) >= GAMMA1 - BETA);
			assert_eq!(z_norm_too_large(&zz), generic, "m = {m}, v = {v}");
		}
	}

	#[test]
	fn sample_in_ball_has_tau_nonzero() {
		let mut c = [0u8; N];
		sample_in_ball(&[7u8; CTILDE_BYTES], &mut c);
		assert_eq!(c.iter().filter(|&&x| x != 0).count(), TAU);
		assert!(c.iter().all(|&x| x == 0 || x == 1 || x == 0xFF));
	}
}
