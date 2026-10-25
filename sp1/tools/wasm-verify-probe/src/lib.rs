//! Minimal wasm exports around `canggu_sp1_verify::verify` for `run.mjs`.

use std::alloc::{alloc, Layout};

/// Allocate `len` bytes for the host to copy an input into (never freed: one-shot probe).
#[no_mangle]
pub extern "C" fn probe_alloc(len: usize) -> *mut u8 {
	// SAFETY: non-zero size, alignment 1.
	unsafe { alloc(Layout::from_size_align(len.max(1), 1).expect("layout")) }
}

/// `1` if the proof verifies, `0` otherwise.
///
/// # Safety
/// The pointers must come from `probe_alloc` with at least the given lengths.
#[no_mangle]
pub unsafe extern "C" fn probe_verify(
	proof: *const u8,
	proof_len: usize,
	pv: *const u8,
	pv_len: usize,
	vk: *const u8,
	vk_len: usize,
) -> u32 {
	let (proof, pv, vk) = unsafe {
		(
			std::slice::from_raw_parts(proof, proof_len),
			std::slice::from_raw_parts(pv, pv_len),
			std::slice::from_raw_parts(vk, vk_len),
		)
	};
	u32::from(canggu_sp1_verify::verify(proof, pv, vk))
}
