//! Selection of the backend behind the `ml_dsa_65_batch_verify` host function.

use canggu_primitives::accel::{self, BatchVerifier, Job, Verification};

/// Backends selectable with `--crypto-backend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
	/// The reference implementation on one core.
	Cpu,
	/// The reference implementation on all cores.
	CpuParallel,
	/// Apple Metal GPU (macOS only). Small batches still go to the CPU, see `--metal-min-batch`.
	Metal,
}

/// Install the chosen backend for this process.
pub fn install(choice: Backend, metal_min_batch: usize) -> sc_cli::Result<()> {
	let backend: Box<dyn BatchVerifier> = match choice {
		Backend::Cpu => Box::new(accel::Cpu),
		Backend::CpuParallel => Box::new(accel::CpuParallel),
		Backend::Metal => Box::new(Metal::new(metal_min_batch)?),
	};
	accel::set_backend(backend)
		.map_err(|_| sc_cli::Error::Input("crypto backend already installed".into()))
}

/// Log the installed backend once the logger is up.
pub fn log_selected() {
	log::info!("⚡ ML-DSA-65 batch verification backend: {}", accel::backend().name());
}

/// ML-DSA-65 batch verification on an Apple GPU.
///
/// The GPU kernels are differentially tested against the CPU reference (`gpu/tests`), and the GPU
/// arithmetic is self-tested at start-up: a GPU that disagreed with the CPU would fork the node
/// off the network, so we refuse to start on one that fails.
struct Metal {
	gpu: canggu_gpu::MetalVerifier,
	min_batch: usize,
}

impl Metal {
	fn new(min_batch: usize) -> sc_cli::Result<Self> {
		let gpu = canggu_gpu::MetalVerifier::new()
			.map_err(|e| sc_cli::Error::Input(format!("Metal backend unavailable: {e}")))?;
		gpu.self_test()
			.map_err(|e| sc_cli::Error::Input(format!("Metal GPU failed its self-test: {e}")))?;
		Ok(Self { gpu, min_batch })
	}
}

impl BatchVerifier for Metal {
	fn name(&self) -> String {
		format!("Metal ({}), batches of {}+ signatures", self.gpu.device_name(), self.min_batch)
	}

	fn verify(&self, jobs: &[Job], ctx: &[u8]) -> Verification {
		if jobs.len() < self.min_batch {
			// A GPU submission costs ~0.2 ms however small the batch; the CPU wins here.
			let mut verification = accel::CpuParallel.verify(jobs, ctx);
			verification.detail = Some(format!("below --metal-min-batch {}", self.min_batch));
			return verification;
		}
		let items: Vec<canggu_gpu::Item> = jobs
			.iter()
			.map(|(public, msg, signature)| canggu_gpu::Item { public, msg, signature })
			.collect();
		let (verdicts, stats) = self.gpu.verify_batch_with_stats(&items, ctx);
		let fallback = match stats.cpu_fallback_jobs {
			0 => String::new(),
			n => format!(", {n} jobs fell back to CPU"),
		};
		Verification {
			verdicts,
			engine: format!("Metal ({})", self.gpu.device_name()),
			detail: Some(format!(
				"GPU busy {:.2?} over {} command buffer(s), CPU prep {:.2?}{fallback}",
				stats.gpu, stats.command_buffers, stats.prepare,
			)),
		}
	}
}
