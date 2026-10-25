# Canggu × SP1: post-quantum proofs and signature compression

This directory holds the [SP1](https://github.com/succinctlabs/sp1) (v6.10.0) side of Canggu: RISC-V
programs proven with SP1's CPU prover into **compressed proofs**. A compressed proof is a hash-based
STARK (KoalaBear field, Poseidon2 Merkle commitments, FRI) with no Groth16/PLONK wrapping, so no
pairings and no elliptic curves anywhere. That makes it plausibly post-quantum. The chain verifies
these proofs through the `sp1_v6_verify_compressed` host function (`primitives/`).

| Program | Statement | Used by |
| --- | --- | --- |
| `programs/mldsa-batch` | every `(pk, msg, sig)` is a valid ML-DSA-65 signature; commits `n ‖ keccak(ctx) ‖ keccak(‖ blake2(pk) ‖ keccak(msg))` | `pallet-pq-intents::submit_compressed` (signature compression) |
| `programs/payroll` | private amounts sum to a public total and open a public commitment | `pallet-zk-verifier::submit_sp1_proof` (post-quantum replacement for the Groth16 circuit) |

Layout:

* `crates/canggu-mldsa`: no_std ML-DSA-65 verifier used inside the guest (adapted from `gpu/`, with
  Keccak routed through SP1's `keccak_permute` precompile), plus the input/public-values encodings.
* `crates/canggu-sp1-prover`: proving API, the `canggu-sp1` binary the wallet calls, and the `bench`
  binary.
* `crates/canggu-sp1-verify`: the only crate the node uses. It depends on `sp1-verifier` only, and
  rejects non-canonical proof encodings (see below).
* `elf/`, `crates/canggu-sp1-verify/vkeys/`: committed program binaries and their vkey hashes. The
  node never needs the SP1 toolchain.
* `fixtures/`, `bench-results/`: real proofs used in tests, and the raw measurements.

## Measurements (Apple M4 Pro, 24 GB, CPU prover)

| | |
| --- | --- |
| Compressed proof size | **1,272,546 B**, for any program and any input size |
| Native verification | **25.5 ms** (≈ 40 ms inside the node's host function, measured live) |
| ML-DSA-65 inside SP1 | 700,713 cycles per signature with the Keccak precompile (1.83 M without) |
| `mldsa-batch` proving | 4 sigs 72 s · 16 sigs 204 s · 64 sigs 617 s · 128 sigs 1,219 s (≈ 9.4 s/sig) |
| Peak memory while proving | 15–17 GB RSS with the memory-safe settings in `scripts/bench-ladder.sh` |
| Break-even vs. raw keys + signatures | **≈ 242 signatures** (1,272,546 / 5,261 B), ≈ 37 min on this laptop |
| `payroll` proving | 16 amounts 50 s · 65,536 amounts 141 s · 262,144 amounts 452 s |

Signature compression *works*, and the chain checks it end to end. On a laptop CPU it costs more
than it saves for any batch that proves in minutes. It becomes worthwhile with GPU provers (SP1's
GPU prover is CUDA-only) and batches of hundreds of signatures, which is the same conclusion as
Rand Protocol's aggregation design.

## Findings worth knowing

* **Proof malleability in the raw verifier.** `sp1-verifier` accepts several byte strings for the
  same valid proof: trailing bytes are ignored, and field elements ≥ p are silently reduced (16 of
  16 tampered Merkle-path words were accepted). `canggu-sp1-verify` requires the canonical
  encoding, and a test shows both the gap and the fix.
* **The verifier is not runtime-ready.** It builds for `wasm32-unknown-unknown` (≈ 3× slower than
  native), but not for `wasm32v1-none`, the target polkadot-sdk runtimes use. Its `full` feature
  pulls in rayon, tokio and crossbeam. Canggu therefore verifies natively, behind a host function.
* **Defaults don't fit 24 GB.** SP1's default worker settings exceeded 33 GB at 16 signatures.
  `canggu-sp1` applies the memory-safe settings automatically.

## Commands

```bash
export CARGO_TARGET_DIR=/tmp/canggu-sp1-target
cargo build --release -p canggu-sp1-prover --bin canggu-sp1     # the prover the wallet calls
export CANGGU_SP1_PROVER=$CARGO_TARGET_DIR/release/canggu-sp1

# against a running node:
canggu zk-sp1 --from //Alice --salt "october payroll" --amounts 3000,4500,1250
canggu intents --count 8 --senders 4 --compressed

cargo test --release --workspace                    # guest logic vs ml-dsa, encodings, zkVM runs
scripts/bench-ladder.sh mldsa 4 16                  # proving measurements
scripts/build-elfs.sh                               # rebuild ELFs (needs `sp1up --version v6.10.0`)
```
