//! Assembles the Metal Shading Language source compiled at runtime.
//!
//! The kernel code lives in `shaders/verify.metal`; this module prepends a prelude generated from
//! the Rust constants and tables, so the GPU and the reference pipeline cannot drift apart.

use crate::{
	arith::{INV_N_MONT, NEG_QINV, R2, ZETAS_MONT},
	keccak::{RHO_PI, ROUND_CONSTANTS, SHAKE128_RATE, SHAKE256_RATE},
	params::{
		CTILDE_BYTES, D, GAMMA1, GAMMA2, K, L, N, Q, T1_POLY_BYTES, W1_BYTES, W1_POLY_BYTES,
		Z_POLY_BYTES,
	},
	prepare::{JOB_BYTES, JOB_C, JOB_CTILDE, JOB_HINT, JOB_MU, JOB_PK, JOB_VALID, JOB_Z},
};
use std::fmt::Write;

const KERNELS: &str = include_str!("shaders/verify.metal");

/// Names of the kernels, in dispatch order.
pub(crate) const KERNEL_NAMES: [&str; 4] = ["ntt_inputs", "expand_a", "rows", "challenge"];

/// Names of the self-test kernels.
pub(crate) const SELFTEST_NAMES: [&str; 3] =
	["selftest_use_hint", "selftest_arith", "selftest_keccak"];

fn table<T: std::fmt::Display>(out: &mut String, decl: &str, values: &[T]) {
	let body: Vec<String> = values.iter().map(|v| v.to_string()).collect();
	let _ = writeln!(out, "{decl} = {{\n\t{}\n}};", body.join(", "));
}

/// The complete shader source.
pub(crate) fn source() -> String {
	let mut s = String::from("#include <metal_stdlib>\nusing namespace metal;\n\n");
	let defines: [(&str, u64); 26] = [
		("Q", Q.into()),
		("D", D.into()),
		("N", N as u64),
		("K", K as u64),
		("L", L as u64),
		("GAMMA1", GAMMA1.into()),
		("GAMMA2", GAMMA2.into()),
		("NEG_QINV", NEG_QINV.into()),
		("R2", R2.into()),
		("INV_N_MONT", INV_N_MONT.into()),
		("CTILDE_BYTES", CTILDE_BYTES as u64),
		("T1_POLY_BYTES", T1_POLY_BYTES as u64),
		("Z_POLY_BYTES", Z_POLY_BYTES as u64),
		("W1_POLY_BYTES", W1_POLY_BYTES as u64),
		("W1_BYTES", W1_BYTES as u64),
		("HASH_IN_BYTES", 64 + W1_BYTES as u64),
		("SHAKE128_RATE", SHAKE128_RATE as u64),
		("SHAKE256_RATE", SHAKE256_RATE as u64),
		("JOB_PK", JOB_PK as u64),
		("JOB_Z", JOB_Z as u64),
		("JOB_HINT", JOB_HINT as u64),
		("JOB_C", JOB_C as u64),
		("JOB_MU", JOB_MU as u64),
		("JOB_CTILDE", JOB_CTILDE as u64),
		("JOB_VALID", JOB_VALID as u64),
		("JOB_BYTES", JOB_BYTES as u64),
	];
	for (name, value) in defines {
		let _ = writeln!(s, "#define {name} {value}u");
	}
	s.push('\n');
	table(&mut s, "constant uint ZETAS_MONT[256]", &ZETAS_MONT);
	let rc: Vec<String> = ROUND_CONSTANTS.iter().map(|c| format!("0x{c:016x}ul")).collect();
	table(&mut s, "constant ulong KECCAK_RC[24]", &rc);
	let (dst, rot): (Vec<usize>, Vec<u32>) = RHO_PI.iter().copied().unzip();
	table(&mut s, "constant uint KECCAK_RHO_PI_DST[25]", &dst);
	table(&mut s, "constant uint KECCAK_RHO_PI_ROT[25]", &rot);
	s.push('\n');
	s.push_str(KERNELS);
	s
}
