# Build and start a chain

> **WARNING:** The development chain uses well-known test keys (`//Alice`, `//Bob` and others).
> Anyone can sign with these keys. Do not use this chain or these keys for real value.

## Get the code

1. Clone the repository:
   ```bash
   git clone https://github.com/agustinustheo/canggu-blockchain.git
   cd canggu-blockchain
   ```

## Build the node and the wallet

1. Build in release mode:
   ```bash
   cargo build --release
   ```
2. Wait for the build to complete. The first build takes approximately 10 to 20 minutes.
3. Make sure that these two files exist:
   - `target/release/canggu-node` (the blockchain node)
   - `target/release/canggu` (the command-line wallet)

> **NOTE:** The build also compiles the runtime to WebAssembly. That step uses the
> `wasm32v1-none` target, which `rust-toolchain.toml` installs.

## Start a development chain

1. Open a terminal. Start one node:
   ```bash
   ./target/release/canggu-node --dev --tmp
   ```
2. Make sure that the log shows new blocks. A new block comes every 2 seconds:
   ```text
   🏆 Imported #1 (0x97ca…83db → 0xd151…ab2a)
   🏆 Imported #2 (0xd151…ab2a → 0x7704…ec82)
   ```
3. Keep this terminal open.

The `--tmp` option keeps the chain data in a temporary folder. The data is deleted when you stop
the node.

### Use the Apple GPU (optional)

On a Mac with Apple silicon, the node can verify batches of signatures on the GPU.

1. Stop the node with **Ctrl+C**.
2. Start it again with the Metal backend:
   ```bash
   ./target/release/canggu-node --dev --tmp --crypto-backend metal
   ```
3. Make sure that the log shows the backend:
   ```text
   ⚡ ML-DSA-65 batch verification backend: Metal (Apple M4 Pro), batches of 64+ signatures
   ```

If the GPU self-test fails, the node does not start. This is intentional: a GPU that gives a
different answer from the CPU would cause the node to disagree with the other validators.

## Run the demonstration

1. Open a second terminal in the repository folder.
2. Run the demonstration:
   ```bash
   ./target/release/canggu demo
   ```
3. Wait approximately one minute. The demonstration sends transactions and waits for blocks.
4. Make sure that the last line is:
   ```text
   All Canggu features exercised successfully.
   ```

The demonstration does these seven steps. Each step is explained in a later chapter.

| Step | What it shows | Chapter |
| --- | --- | --- |
| 1 | A transfer signed with ML-DSA-65 (5,345 bytes) | [Post-quantum accounts](../features/post-quantum-accounts.md) |
| 2 | A transaction that waits for another account's transaction | [Transactions that wait for each other](../features/dag-ordering.md) |
| 3 | A transaction with a tip is refused | [Transactions that wait for each other](../features/dag-ordering.md#no-tips-no-priority-auction) |
| 4 | One payroll transaction pays four people | [Parallel payroll](../features/payroll.md) |
| 5 | A Groth16 proof of a private payroll, checked on-chain | [Zero-knowledge proofs](../features/zk-proofs.md) |
| 6 | 64 signed intents checked with one host call (on the GPU if enabled) | [GPU verification](../features/gpu.md) |
| 7 | Commit, reveal in reverse order, execute in canonical order | [Sealed ordering](../features/sealed-ordering.md) |

## Stop the chain

1. Go to the terminal that runs the node.
2. Push **Ctrl+C**.

## Run two validators

Two scripts start two validators (Alice and Bob) on the same computer.

| Script | What it does |
| --- | --- |
| `scripts/mixed-backends.sh` | Alice verifies signatures on the GPU, Bob on one CPU core. The script shows that both keep the same blocks. It needs the Metal GPU. On other computers, set `ALICE_BACKEND=cpu-parallel`. |
| `scripts/finality.sh` | It measures the time from a new block to its finalisation. |

1. Make sure that no other node is running.
2. Make sure that `curl` is installed. The scripts use it.
3. Run a script from the repository folder:
   ```bash
   scripts/mixed-backends.sh 6 256
   ```
4. Make sure that the output contains `identical`:
   ```text
   blocks 1..11: identical
   finalized: alice #11, bob #11
   ```

> **CAUTION:** The two validators use the ports 30333, 30334, 9944 and 9945. Stop other
> programs that use these ports before you start a script.
