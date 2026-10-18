//! Pluggable backends for batch signature verification (std only).
//!
//! The `ml_dsa_65_batch_verify` host function is consensus-critical: every node must return the
//! same `Vec<bool>` for the same input. The CPU reference ([`keyring::verify`]) defines the answer.
//! A node may install any other backend (multi-core CPU, Apple Metal, CUDA, ...) at startup with
//! [`set_backend`], as long as it is bit-for-bit equivalent to the reference. Backends are a node
//! implementation detail and never visible to the runtime.

use crate::keyring;
use std::{
	sync::OnceLock,
	time::{Duration, Instant},
};

/// One verification job: `(public key, message, signature)`.
pub type Job = (Vec<u8>, Vec<u8>, Vec<u8>);

/// The outcome of one batch.
pub struct Verification {
	/// One verdict per job. Must equal [`keyring::verify_with_context`] item by item.
	pub verdicts: Vec<bool>,
	/// What actually did the work, e.g. `"Metal (Apple M4 Pro)"`.
	pub engine: String,
	/// Optional backend-specific detail for the log, e.g. GPU busy time.
	pub detail: Option<String>,
}

/// A batch ML-DSA-65 verifier.
pub trait BatchVerifier: Send + Sync {
	/// Human readable name for logs, e.g. `"Metal (Apple M4 Pro)"`.
	fn name(&self) -> String;
	/// Verify every job with FIPS 204 context `ctx`.
	fn verify(&self, jobs: &[Job], ctx: &[u8]) -> Verification;
}

/// The reference implementation, one core.
pub struct Cpu;

impl BatchVerifier for Cpu {
	fn name(&self) -> String {
		"CPU (1 core)".into()
	}

	fn verify(&self, jobs: &[Job], ctx: &[u8]) -> Verification {
		let verdicts = jobs
			.iter()
			.map(|(pk, msg, sig)| keyring::verify_with_context(pk, msg, sig, ctx))
			.collect();
		Verification { verdicts, engine: self.name(), detail: None }
	}
}

/// The reference implementation spread over all cores.
pub struct CpuParallel;

impl BatchVerifier for CpuParallel {
	fn name(&self) -> String {
		format!("CPU ({} cores)", rayon::current_num_threads())
	}

	fn verify(&self, jobs: &[Job], ctx: &[u8]) -> Verification {
		use rayon::prelude::*;
		let verdicts = jobs
			.par_iter()
			.map(|(pk, msg, sig)| keyring::verify_with_context(pk, msg, sig, ctx))
			.collect();
		Verification { verdicts, engine: self.name(), detail: None }
	}
}

static BACKEND: OnceLock<Box<dyn BatchVerifier>> = OnceLock::new();

/// Install the process-wide backend. Can only be done once, before the first batch.
pub fn set_backend(backend: Box<dyn BatchVerifier>) -> Result<(), Box<dyn BatchVerifier>> {
	BACKEND.set(backend)
}

/// The installed backend, defaulting to [`CpuParallel`].
pub fn backend() -> &'static dyn BatchVerifier {
	BACKEND.get_or_init(|| Box::new(CpuParallel)).as_ref()
}

/// Verify a batch with the installed backend and log how long it took.
pub fn verify_batch(jobs: &[Job], ctx: &[u8]) -> Vec<bool> {
	let started = Instant::now();
	let verification = backend().verify(jobs, ctx);
	log_batch(jobs.len(), &verification, started.elapsed());
	verification.verdicts
}

fn log_batch(n: usize, verification: &Verification, elapsed: Duration) {
	let valid = verification.verdicts.iter().filter(|ok| **ok).count();
	let detail = verification.detail.as_ref().map(|d| format!(" ({d})")).unwrap_or_default();
	log::info!(
		target: "canggu-accel",
		"⚡ {}: batch-verified {n} ML-DSA-65 signatures ({valid} valid) in {elapsed:.2?}{detail}",
		verification.engine,
	);
}
