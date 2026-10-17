//! Selection of the backend behind the `ml_dsa_65_batch_verify` host function.

use canggu_primitives::accel::{self, BatchVerifier};

/// Backends selectable with `--crypto-backend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
	/// The reference implementation on one core.
	Cpu,
	/// The reference implementation on all cores.
	CpuParallel,
	/// Apple Metal GPU (macOS only).
	Metal,
}

/// Install the chosen backend for this process.
pub fn install(choice: Backend) -> sc_cli::Result<()> {
	let backend: Box<dyn BatchVerifier> = match choice {
		Backend::Cpu => Box::new(accel::Cpu),
		Backend::CpuParallel => Box::new(accel::CpuParallel),
		Backend::Metal => metal()?,
	};
	accel::set_backend(backend)
		.map_err(|_| sc_cli::Error::Input("crypto backend already installed".into()))
}

/// Log the installed backend once the logger is up.
pub fn log_selected() {
	log::info!("⚡ ML-DSA-65 batch verification backend: {}", accel::backend().name());
}

fn metal() -> sc_cli::Result<Box<dyn BatchVerifier>> {
	Err(sc_cli::Error::Input("the Metal backend is not available in this build".into()))
}
