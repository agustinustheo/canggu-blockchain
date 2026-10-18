//! Batch verification of ML-DSA-65 (FIPS 204) signatures on Apple Metal GPUs.
//!
//! Verification (FIPS 204 Algorithm 3 `ML-DSA.Verify` / Algorithm 8 `Verify_internal`) is split
//! into two stages:
//!
//! 1. **CPU pre-processing** (`prepare` module): length checks, `sigDecode` validation (hint
//!    encoding, `||z||_inf < gamma1 - beta`), `tr = H(pk)`, `mu = H(tr || 0 || |ctx| || ctx || M)`
//!    and `c = SampleInBall(c~)`. This is cheap and variable-length. Items that fail are rejected
//!    here; the rest become fixed-size job records.
//! 2. **Lattice stage** (four kernels): `ExpandA` via SHAKE128 rejection sampling (the dominant
//!    cost, 30 polynomials per signature), the NTTs of `z`, `c` and `t1 * 2^d`, `w' = NTT^-1(A o z
//!    - c o t1 * 2^d)`, `UseHint`, `w1Encode` and `c~' = H(mu || w1)`.
//!
//! [`MetalVerifier`] runs stage 2 on the GPU; large batches are split into a few sub-batches
//! so that stage 1 of one overlaps stage 2 of the previous one. [`verify_batch_reference`] runs
//! the very same stage-2 kernels as plain Rust functions (`reference` module), sharing the
//! stage-1 code, tables and constants. It is the oracle used to check the GPU bit for bit, and
//! is itself checked against the RustCrypto `ml-dsa` crate in the tests.
//! [`MetalVerifier::self_test`] additionally compares the GPU building blocks with their Rust
//! twins on edge cases that real signatures never reach.
//!
//! Only integer arithmetic is used, so results are deterministic across devices and runs.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod arith;
mod keccak;
pub mod params;
mod prepare;
mod reference;
#[cfg(target_os = "macos")]
mod shader;

#[cfg(target_os = "macos")]
mod metal;
#[cfg(target_os = "macos")]
pub use metal::{MetalVerifier, MAX_JOBS_PER_SUBMISSION};

use prepare::JOB_BYTES;
use std::time::Duration;

/// One signature to verify. All fields are untrusted bytes.
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
	/// Encoded ML-DSA-65 public key (`pkEncode`, 1952 bytes when well-formed).
	pub public: &'a [u8],
	/// The message `M`.
	pub msg: &'a [u8],
	/// Encoded signature (`sigEncode`, 3309 bytes when well-formed).
	pub signature: &'a [u8],
}

/// Errors when setting up a GPU verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	/// Metal is not available on this platform.
	Unsupported,
	/// No Metal device (or command queue) could be created.
	NoDevice,
	/// The embedded Metal shader failed to compile.
	ShaderCompile(String),
	/// A compute pipeline could not be created.
	Pipeline(String),
	/// The GPU disagreed with the CPU reference in [`MetalVerifier::self_test`].
	SelfTest(String),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Unsupported => write!(f, "Metal is only supported on macOS"),
			Error::NoDevice => write!(f, "no Metal device available"),
			Error::ShaderCompile(e) => write!(f, "Metal shader compilation failed: {e}"),
			Error::Pipeline(e) => write!(f, "Metal pipeline creation failed: {e}"),
			Error::SelfTest(e) => write!(f, "GPU self-test failed: {e}"),
		}
	}
}

impl std::error::Error for Error {}

/// Timing breakdown of one [`MetalVerifier::verify_batch_with_stats`] call.
#[derive(Debug, Default, Clone, Copy)]
pub struct BatchStats {
	/// Wall time of the whole call (CPU pre-processing, GPU, post-processing).
	pub total: Duration,
	/// Wall time spent in CPU pre-processing (stage 1, multi-threaded).
	pub prepare: Duration,
	/// Sum of `GPUEndTime - GPUStartTime` over all command buffers, as reported by Metal.
	pub gpu: Duration,
	/// Number of command buffers submitted.
	pub command_buffers: usize,
	/// Number of job records processed by the GPU.
	pub gpu_jobs: usize,
	/// Number of jobs that had to be evaluated on the CPU because of a Metal error.
	pub cpu_fallback_jobs: usize,
}

/// Stand-in for the GPU verifier on platforms without Metal; [`MetalVerifier::new`] always fails.
#[cfg(not(target_os = "macos"))]
pub struct MetalVerifier {
	_private: (),
}

#[cfg(not(target_os = "macos"))]
impl MetalVerifier {
	/// Always returns [`Error::Unsupported`].
	pub fn new() -> Result<Self, Error> {
		Err(Error::Unsupported)
	}

	/// Unreachable in practice, as no instance can be constructed.
	pub fn device_name(&self) -> String {
		String::new()
	}

	/// Unreachable in practice, as no instance can be constructed; falls back to the reference.
	pub fn verify_batch(&self, items: &[Item], ctx: &[u8]) -> Vec<bool> {
		verify_batch_reference(items, ctx)
	}

	/// Unreachable in practice, as no instance can be constructed; falls back to the reference.
	pub fn verify_batch_with_stats(&self, items: &[Item], ctx: &[u8]) -> (Vec<bool>, BatchStats) {
		let stats = BatchStats { cpu_fallback_jobs: items.len(), ..Default::default() };
		(verify_batch_reference(items, ctx), stats)
	}

	/// Always returns [`Error::Unsupported`].
	pub fn self_test(&self) -> Result<(), Error> {
		Err(Error::Unsupported)
	}

	/// Always returns `None`.
	pub fn profile_kernels(
		&self,
		_items: &[Item],
		_ctx: &[u8],
	) -> Option<Vec<(&'static str, Duration)>> {
		None
	}
}

/// Pure-Rust verification that executes the GPU pipeline step by step on the CPU.
///
/// Returns, for every item, what `ml-dsa`'s `verify_with_context(msg, ctx, sig)` returns.
pub fn verify_batch_reference(items: &[Item], ctx: &[u8]) -> Vec<bool> {
	let mut job = vec![0u8; JOB_BYTES];
	let mut scratch = reference::Scratch::new();
	items
		.iter()
		.map(|item| {
			prepare::prepare_job(item, ctx, &mut job) && reference::run_job(&job, &mut scratch)
		})
		.collect()
}

/// Run stage 1 for all `items` into consecutive [`JOB_BYTES`] records of `jobs`, spreading the
/// work over the available CPU cores for larger batches. Returns the per-item validity.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn prepare_jobs(items: &[Item], ctx: &[u8], jobs: &mut [u8]) -> Vec<bool> {
	debug_assert_eq!(jobs.len(), items.len() * JOB_BYTES);
	/// Below this many items per thread, spawning threads costs more than it saves.
	const MIN_ITEMS_PER_THREAD: usize = 16;
	let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
	let threads = threads.min(items.len() / MIN_ITEMS_PER_THREAD).max(1);
	let mut valid = vec![false; items.len()];
	if threads == 1 {
		for ((item, job), v) in items.iter().zip(jobs.chunks_mut(JOB_BYTES)).zip(&mut valid) {
			*v = prepare::prepare_job(item, ctx, job);
		}
		return valid;
	}
	let per_thread = items.len().div_ceil(threads);
	std::thread::scope(|scope| {
		for ((items, jobs), valid) in items
			.chunks(per_thread)
			.zip(jobs.chunks_mut(per_thread * JOB_BYTES))
			.zip(valid.chunks_mut(per_thread))
		{
			scope.spawn(move || {
				for ((item, job), v) in items.iter().zip(jobs.chunks_mut(JOB_BYTES)).zip(valid) {
					*v = prepare::prepare_job(item, ctx, job);
				}
			});
		}
	});
	valid
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn verifier_is_send_and_sync() {
		fn assert_send_sync<T: Send + Sync>() {}
		assert_send_sync::<MetalVerifier>();
	}

	#[test]
	fn malformed_lengths_are_rejected() {
		let pk = vec![0u8; params::PUBLIC_KEY_BYTES];
		let sig = vec![0u8; params::SIGNATURE_BYTES];
		let items = [
			Item { public: &pk[1..], msg: b"", signature: &sig },
			Item { public: &pk, msg: b"", signature: &sig[1..] },
			Item { public: &[], msg: b"", signature: &[] },
		];
		assert_eq!(verify_batch_reference(&items, b""), vec![false; 3]);
	}
}
