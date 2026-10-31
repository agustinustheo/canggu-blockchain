# Repository map

| Path | Crate | What it contains | Read about it in |
| --- | --- | --- | --- |
| `primitives/` | `canggu-primitives` | `CangguSignature`, the host functions, backend selection, development keys | [Post-quantum accounts](../features/post-quantum-accounts.md) |
| `pallets/dag-ordering/` | `canggu-dag-ordering` | `CheckDagParents`, `ChargeTransactionPaymentNoTip` | [Transactions that wait for each other](../features/dag-ordering.md) |
| `pallets/sealed-ordering/` | `pallet-sealed-ordering` | Commit, reveal, canonical execution | [Sealed ordering](../features/sealed-ordering.md) |
| `pallets/zk-verifier/` | `pallet-zk-verifier` | Groth16 and SP1 proof verification | [Zero-knowledge proofs](../features/zk-proofs.md) |
| `pallets/pq-intents/` | `pallet-pq-intents` | Batches of signed intents; compressed batches | [Signature compression](../features/signature-compression.md) |
| `pallets/parallel-payroll/` | `pallet-parallel-payroll` | One debit, conflict-free credits | [Parallel payroll](../features/payroll.md) |
| `zk/` | `canggu-zk` | Groth16 private-payroll circuit (off-chain) | [Zero-knowledge proofs](../features/zk-proofs.md) |
| `gpu/` | `canggu-gpu` | ML-DSA-65 batch verification on Metal, CPU copy, tests | [GPU verification](../features/gpu.md) |
| `gpu/bench/` | `canggu-gpu-bench` | Metal vs CPU benchmark | [All the numbers](../results/numbers.md) |
| `runtime/` | `canggu-runtime` | The FRAME runtime that combines all pallets | [The big picture](../background/architecture.md) |
| `node/` | `canggu-node` | The node: Aura, GRANDPA, host functions, backend and finality options | [The Polkadot SDK in ten minutes](../background/polkadot-sdk-primer.md) |
| `cli/` | `canggu-cli` | The `canggu` wallet, demo and benchmarks | [Use the `canggu` command line](../getting-started/cli.md) |
| `sp1/` | separate workspace | SP1 programs (`mldsa-batch`, `payroll`), the `canggu-sp1` prover, `canggu-sp1-verify` | [Signature compression](../features/signature-compression.md) |
| `scripts/` | — | `mixed-backends.sh`, `finality.sh` | [Build and start a chain](../getting-started/build-and-run.md) |
| `docs/` | — | This book | [About these docs](about-these-docs.md) |

The Polkadot SDK version is `polkadot-stable2609`. The node and runtime started from the SDK's
solochain template.
