#!/usr/bin/env bash
# Rebuild the SP1 guest ELFs into `elf/` (requires `sp1up --version v6.10.0`, i.e. `cargo prove`
# and the `succinct` Rust toolchain). After rebuilding, refresh the committed vkey hashes with
# `cargo run --release -p canggu-sp1-prover --bin bench -- vkeys`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/canggu-sp1-target}"
export PATH="$HOME/.sp1/bin:$PATH"
cd "$ROOT/programs/mldsa-batch"
cargo prove build --locked --output-directory "$ROOT/elf" --elf-name mldsa-batch.elf
cargo prove build --locked --no-default-features --output-directory "$ROOT/elf" \
	--elf-name mldsa-batch-soft-keccak.elf
cd "$ROOT/programs/payroll"
cargo prove build --locked --output-directory "$ROOT/elf" --elf-name payroll.elf
ls -l "$ROOT/elf"
