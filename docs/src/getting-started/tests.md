# Run the tests

## Run the main test suite

1. Go to the repository folder.
2. Run all tests:
   ```bash
   cargo test --release --workspace
   ```
3. Make sure that all tests pass. The main workspace has 67 tests. One of them is marked
   `ignored`: it only writes a test fixture. The result line shows `66 passed; 1 ignored`.

The tests include:

- **Runtime tests** that send real ML-DSA-signed transactions through the runtime. They make sure
  that valid transfers execute, and that changed signatures, substituted keys, a transaction
  before its parent, and tips are refused.
- **Pallet tests** for each Canggu pallet. Some use real SP1 proofs that are stored in the
  repository.
- **GPU tests** that compare the Metal kernels with two CPU implementations on 5,454 test cases.

> **CAUTION:** The GPU tests need an Apple GPU. They are not tested on other computers.

## Run the SP1 tests

The SP1 programs are in a separate workspace in the `sp1/` folder.

1. Run the tests:
   ```bash
   cd sp1
   export CARGO_TARGET_DIR=/tmp/canggu-sp1-target
   cargo test --release --workspace
   ```
   The SP1 workspace has 23 tests. Two of them are marked `ignored`, because they make full
   proofs, which take minutes.
2. Run the verifier tests. The verifier crate has its own workspace:
   ```bash
   cd crates/canggu-sp1-verify
   cargo test --release
   ```

## Run the GPU benchmark

1. Run the benchmark:
   ```bash
   cargo run --release --bin bench
   ```
2. Read the table. It compares one CPU core, all CPU cores and the GPU for batches of 1 to 4,096
   signatures.

## Check the code style

1. Run the formatter. It needs a nightly Rust toolchain:
   ```bash
   cargo +nightly fmt --all -- --check
   ```
2. Run Clippy:
   ```bash
   SKIP_WASM_BUILD=1 cargo clippy --release --workspace --all-targets
   ```
