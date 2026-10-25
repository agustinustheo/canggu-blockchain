//! `canggu-sp1`: the prover the Canggu wallet calls. Kept out of the node and wallet so that
//! neither links the SP1 SDK.
//!
//! ```text
//! canggu-sp1 prove <mldsa|payroll> <input.bin> <out-prefix>
//! ```
//!
//! `input.bin` is the guest input exactly as the guest reads it (`canggu_mldsa::batch::encode_input`
//! or `canggu_mldsa::payroll::encode_input`). Writes `<out-prefix>.proof` (bincode, as
//! `canggu-sp1-verify` expects) and `<out-prefix>.pv` (public values), and prints a one-line
//! summary. Memory-conservative SP1 settings that fit a 24 GB machine are used unless the
//! `SP1_WORKER_*` / `*_THRESHOLD` variables are already set (see `scripts/bench-ladder.sh`).

use anyhow::{bail, Context, Result};
use canggu_sp1_prover::{prove, Program};
use std::time::Instant;

/// Defaults from `scripts/bench-ladder.sh`: peak footprint ~20 GB at ~15% extra wall time.
const MEMORY_SAFE_DEFAULTS: &[(&str, &str)] = &[
	("SP1_WORKER_NUM_CORE_WORKERS", "1"),
	("SP1_WORKER_CORE_BUFFER_SIZE", "1"),
	("SP1_WORKER_NUM_RECURSION_PROVER_WORKERS", "2"),
	("SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE", "2"),
	("SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS", "2"),
	("SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE", "2"),
	("SP1_WORKER_NUM_SPLICING_WORKERS", "1"),
	("SP1_WORKER_SPLICING_BUFFER_SIZE", "1"),
	("ELEMENT_THRESHOLD", "201326592"),
	("HEIGHT_THRESHOLD", "2097152"),
];

fn main() -> Result<()> {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let [cmd, program, input, prefix] = args.as_slice() else {
		bail!("usage: canggu-sp1 prove <mldsa|payroll> <input.bin> <out-prefix>");
	};
	if cmd != "prove" {
		bail!("unknown command {cmd}");
	}
	let program = match program.as_str() {
		"mldsa" => Program::MldsaBatch,
		"payroll" => Program::Payroll,
		other => bail!("unknown program {other}"),
	};
	for (key, value) in MEMORY_SAFE_DEFAULTS {
		if std::env::var_os(key).is_none() {
			// SAFETY: single-threaded at this point; nothing else reads the environment yet.
			unsafe { std::env::set_var(key, value) };
		}
	}
	let input = std::fs::read(input).with_context(|| format!("reading {input}"))?;
	let started = Instant::now();
	let proved = prove(program, input)?;
	let seconds = started.elapsed().as_secs_f64();
	std::fs::write(format!("{prefix}.proof"), &proved.proof)?;
	std::fs::write(format!("{prefix}.pv"), &proved.public_values)?;
	println!(
		"{} proved: {} cycles, {} byte proof, {:.1} s -> {prefix}.proof",
		program.name(),
		proved.cycles,
		proved.proof.len(),
		seconds
	);
	Ok(())
}
