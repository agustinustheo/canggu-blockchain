# Canggu on the Polkadot SDK

**How far can the Polkadot SDK be pushed?** This repository rebuilds *Canggu*, a quantum-secure,
MEV-resistant, GPU-parallel blockchain designed by the Bitwyre team, on top of the
[Polkadot SDK](https://github.com/paritytech/polkadot-sdk) (`polkadot-stable2609`).

It is an experiment, not an endorsement. The goal is to take an ambitious design and see which parts
map cleanly onto Substrate/FRAME, which need new primitives, and where the hard limits are,
including whether a Polkadot SDK node can put real work on a GPU. **It can:** blocks containing
hundreds of post-quantum signatures are verified on an Apple M4 Pro GPU through Metal, while a
second validator verifies the same blocks on its CPU, and the two stay in consensus
([details](#polkadot-sdk-on-a-gpu)).

> **Credits.** Canggu, its design and its original whitepaper are the work of
> **Dendi Suhubdy, Tejveer Singh, Mitul Dhawan and Maldini Sonkeng (Bitwyre)**. The original
> repository was set up by **Dendi Suhubdy** and **Mitul Dhawan** ([@mitul72](https://github.com/mitul72)),
> and its first commits are preserved in this repository's history. They open-sourced the project;
> this fork keeps their GPL-3.0 license. Everything built on top is an independent rebuild of their
> idea. Credit for the idea is theirs, and mistakes in the rebuild are ours.
>
> * Original whitepaper (v1.3): [`canggu-blockchain-whitepaper`](https://github.com/agustinustheo/canggu-blockchain-whitepaper)
> * Polkadot SDK edition of the whitepaper (v2.0), describing this code: [`v2/main.pdf`](https://github.com/agustinustheo/canggu-blockchain-whitepaper/blob/main/v2/main.pdf)

## What runs today

```
$ ./target/release/canggu demo
=== 1. Post-quantum accounts (ML-DSA-65 / CRYSTALS-Dilithium3) ===
  Alice -> Dave 100 CGU: 5345 byte extrinsic (1952-byte key + 3309-byte signature inside)
=== 2. DAG-ordered transactions (cross-account dependencies) ===
  submitting Charlie's tx FIRST; it declares Bob's tx (nonce 0) as parent
  2 blocks later the child is still not in any block: it waits for its parent
  parent: block #6 index 1 | child: block #6 index 2
=== 3. No priority auction: tips are rejected ===
  rejected by the pool as expected: Invalid Transaction: "Custom error: 0"
=== 4. Payroll: one debit, conflict-free parallel credits ===
  batch paying Bob twice: rejected with Payroll::DuplicateRecipient
=== 5. zk-SNARK: prove a private payroll off-chain, verify on-chain ===
  proof generated on CPU in 32.7ms: 192 bytes
  ok: the chain verified the payroll total without seeing any salary
  same proof, claimed total + 1: rejected with ZkVerifier::InvalidProof
=== 6. Post-quantum intents: one batch, one (GPU-accelerable) host call ===
  block #13: 62 intents executed, 2 rejected {"BadSignature": 2}
All Canggu features exercised successfully.
```

| Canggu idea (v1.3) | How it maps onto the Polkadot SDK | Status |
| --- | --- | --- |
| Dilithium signatures | New `CangguSignature::MlDsa65` account signature, verified by a native **host function** | ✅ |
| Quantum-resistant hashing | BLAKE2b-256 already gives 128-bit post-quantum preimage security | ✅ |
| DAG mempool | The transaction pool is *already* a tag DAG. `CheckDagParents` adds cross-account edges, enforced by consensus | ✅ |
| MEV mitigation | Dependency enforcement + **no tips** (no priority-fee auction) | 🟡 encrypted mempool still needed |
| Tower-BFT-style leader consensus | Aura (2 s round-robin leader slots) + GRANDPA finality | ✅ (not sub-second) |
| ZK-SNARK verifiers / provers | Groth16 verifier pallet + host function; off-chain prover | ✅ (not post-quantum) |
| GPU acceleration | Batch ML-DSA verification on **Apple Metal**, behind a runtime host function | ✅ |
| Parallel CPU/GPU contracts | Conflict-free batch payroll; general GPU contracts are not deterministic | 🟡 |
| 50,000+ TPS | Measured: bandwidth-bound at ~370 PQ transfers/s | ❌ needs signature compression |

## Architecture

```mermaid
flowchart LR
  subgraph Client
    W["canggu CLI<br/>ML-DSA-65 keys"]
    P["Off-chain prover<br/>Groth16 / arkworks"]
  end
  subgraph Node["canggu-node (native)"]
    TP["Transaction pool<br/>provides/requires DAG"]
    C["Aura leader slots<br/>+ GRANDPA finality"]
    X["Wasm executor"]
    H["Host functions<br/>ml_dsa_65_verify<br/>ml_dsa_65_batch_verify<br/>groth16_bls12_381_verify"]
    G["Metal GPU<br/>(--crypto-backend metal)"]
  end
  subgraph Runtime["canggu-runtime (Wasm, on-chain)"]
    S["CangguSignature"]
    D["CheckDagParents<br/>ChargeTransactionPaymentNoTip"]
    Z["pallet-zk-verifier"]
    PP["pallet-parallel-payroll"]
    I["pallet-pq-intents"]
  end
  W -- signed tx --> TP --> C --> X --> Runtime
  P -- proof tx --> TP
  S -. calls .-> H
  Z -. calls .-> H
  I -. one call per batch .-> H
  H -- batch --> G
```

The core trick is to keep consensus logic in the Wasm runtime and move **heavy cryptography into
host functions**. A host function is a fixed bytes-in, bool-out contract that the node implements
natively. That is how Substrate verifies sr25519 today, and it is the one place where a node can
swap a CPU implementation for a GPU one without changing consensus.

## The pieces

### Post-quantum accounts: `primitives/`
* Accounts are `blake2_256(ml_dsa_public_key)`. A 1,952-byte key cannot be an `AccountId32`, so the
  signature carries the key and verification first checks that it hashes to the sender. This
  prevents key substitution and costs one hash.
* FIPS 204 context string `canggu/tx/v1` for domain separation, deterministic signing.
* Ed25519, Sr25519 and ECDSA stay as *transition-period* variants (same encoding indices as
  `MultiSignature`), so polkadot.js and subxt still work. A runtime upgrade can retire them.

### DAG-ordered transactions: `pallets/dag-ordering/`
* `CheckDagParents` lets a transaction declare up to 8 parents as `(account, nonce)`, including
  other accounts' transactions.
* Pending parents become `requires` tags with the exact encoding `frame_system::CheckNonce` uses
  for `provides`, so Substrate's existing ready/future queues do the topological ordering.
* The same check runs again when the block executes. A block that puts a child before its parent is
  **invalid**. The check runs *before* `CheckNonce`, so a rejected transaction mutates nothing.
* `ChargeTransactionPaymentNoTip` is the stock fee extension with tips rejected. Priority can no
  longer be bought.

### zk-SNARKs: `pallets/zk-verifier/`, `zk/`
* Circuit-agnostic Groth16/BLS12-381 verifier pallet. Verified `(vk, inputs)` statements are recorded.
* Example *private payroll* circuit: prove that hidden 64-bit salaries sum to a public total and open
  a public MiMC commitment, without revealing any salary.

### Post-quantum intents: `pallets/pq-intents/`
* Users sign transfer *intents* off-chain. A relayer submits up to 640 of them in one extrinsic.
* The runtime verifies the whole batch with **one** host call, `ml_dsa_65_batch_verify`, which is the
  call a node can run on a GPU. Each intent then succeeds or is rejected on its own (bad signature,
  stale nonce, failed transfer).

### Parallel payroll: `pallets/parallel-payroll/`
* `batch_pay` debits the employer once, then credits distinct recipients. Distinctness is enforced,
  so the credits touch disjoint state and commute, which is the property a parallel executor needs.

## Numbers (Apple M4 Pro, release build)

| | |
| --- | --- |
| ML-DSA-65 verify (native host fn, 1 core) | **61 µs** |
| ML-DSA-65 batch verify on Metal, 4,096 sigs | **6.5 ms** (630k sig/s, 4.45× all 12 CPU cores) |
| ML-DSA-65 transfer extrinsic | **5,345 B** (vs ~150 B for sr25519) |
| Groth16 verify, payroll circuit (any size) | **2.3 ms**, 192 B proof |
| Groth16 prove, 1,024 salaries (405k constraints) | 2.0 s on 12 cores |
| Capacity with 5 MiB blocks / 2 s slots | ~370 PQ transfers/s, **bandwidth-bound** |

## What did not survive contact with the code

Building the design surfaced a few claims from v1.3 that don't hold. They're documented in the v2.0
whitepaper, and the most important ones are:

* **Kyber can't sign transactions.** It's a key-encapsulation mechanism. Accounts use ML-DSA, and
  ML-KEM is reserved for an encrypted mempool.
* **XMSS isn't a hash function.** It's a stateful signature scheme.
* **BLS12-381 SNARKs aren't quantum-resistant.** Shor's algorithm breaks pairings, and STARKs are
  the post-quantum path.
* **A DAG doesn't make MEV computationally hard.** Topological sorting is linear and any linear
  extension is valid. The DAG enforces the dependencies users *declare*. Front-running independent
  transactions needs encryption.
* **50k TPS with 3.3 kB signatures** would mean ~265 MB/s of gossip. That needs signature
  compression (a STARK over the block's signatures), which is where the GPU and ZK pillars meet.

## Polkadot SDK on a GPU?

The Wasm runtime itself can't sensibly run on a GPU. Every validator must compute bit-identical state
roots, execution must be metered, and GPU kernels can't touch the state trie. So this rebuild goes as
close to the GPU as the Polkadot SDK allows: **the runtime stays deterministic Wasm, and makes one
host call per batch that the node executes on the GPU.**

```
runtime (Wasm)  pallet-pq-intents::submit_intents(640 signed intents)
      │  canggu_crypto::ml_dsa_65_batch_verify(batch)          ← one host call
node (native)   accel backend chosen with --crypto-backend
      ├─ cpu            reference implementation, 1 core      ← defines the correct answer
      ├─ cpu-parallel   reference implementation, all cores   (default)
      └─ metal          gpu/: FIPS 204 Verify as Metal compute kernels
                          CPU: decode, hint/z checks, tr, μ, challenge
                          GPU: NTTs → ExpandA × z → UseHint/w1Encode → SHAKE256 compare
```

### Proof that it runs on the GPU

**1. A live chain, verifying on Metal.** `canggu-node --dev --crypto-backend metal`, then
`canggu intents --count 640 --forge 4`:

```
⚡ ML-DSA-65 batch verification backend: Metal (Apple M4 Pro), batches of 64+ signatures
⚡ Metal (Apple M4 Pro): batch-verified 640 ML-DSA-65 signatures (636 valid) in 8.36ms (GPU busy 4.12ms over 1 command buffer(s), CPU prep 968.21µs)
⚡ Metal (Apple M4 Pro): batch-verified 256 ML-DSA-65 signatures (252 valid) in 5.24ms (GPU busy 1.66ms over 1 command buffer(s), CPU prep 652.50µs)
⚡ CPU (12 cores): batch-verified 32 ML-DSA-65 signatures (28 valid) in 749.13µs (below --metal-min-batch 64)
```

"GPU busy" is measured by Metal itself (`MTLCommandBuffer` `GPUStartTime`/`GPUEndTime`). The four
forged intents in each batch were rejected on the GPU.

**2. Consensus across different hardware.** [`scripts/mixed-backends.sh`](scripts/mixed-backends.sh)
runs two validators: Alice verifies on Metal, Bob on one CPU core. Aura alternates authors, so every
batch is verified by the GPU on one validator and by the CPU on the other. Had they disagreed on a
single signature, the importing node would compute a different state root and reject the block.

```
#6:  authored by Alice (metal), imported by Bob (cpu)
#7:  authored by Bob (cpu), imported by Alice (metal)
#8:  authored by Alice (metal), imported by Bob (cpu)
#9:  authored by Bob (cpu), imported by Alice (metal)
#10: authored by Alice (metal), imported by Bob (cpu)
#11: authored by Bob (cpu), imported by Alice (metal)
blocks 1..11: identical
finalized: alice #11, bob #11
```

**3. Bit-exactness tests.** `cargo test --release -p canggu-gpu` checks the Metal kernels, a
pure-Rust mirror of each kernel, and the RustCrypto `ml-dsa` crate against each other on 5,454 items:
2,504 valid signatures, and 2,950 corrupted ones (bit flips in every field, malformed hints, z at the
bound, wrong contexts and lengths). All three agree on every item. A GPU self-test, which also runs
at node start-up, checks UseHint for **every** value below q, the modular arithmetic and Keccak-f
against the CPU. It caught a planted off-by-one that real signatures never exercise.

**4. Throughput** (`cargo run --release --bin bench`, Apple M4 Pro, medians; wall time includes CPU
pre-processing and transfers):

| batch | ml-dsa, 1 core | ml-dsa, 12 cores | Metal | GPU busy | Metal vs 12 cores |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.060 ms | 0.060 ms | 0.330 ms | 0.203 ms | 0.18× |
| 64 | 3.77 ms | 0.61 ms | 0.45 ms | 0.23 ms | 1.35× |
| 256 | 15.2 ms | 1.95 ms | 0.85 ms | 0.43 ms | 2.29× |
| 1024 | 61.2 ms | 7.52 ms | 2.12 ms | 1.50 ms | 3.55× |
| 4096 | 246 ms | 29.0 ms | 6.51 ms | 5.59 ms | **4.45×** (630k sig/s) |

Honest caveats:

* Below ~64 signatures the fixed ~0.2 ms GPU submission cost loses to the CPU, so the node routes
  small batches to the CPU.
* In the live node, a batch costs more than in the warm benchmark. The node also copies the batch
  across the host-function boundary, and on this machine macOS's photo-analysis service was keeping
  the GPU busy at the same time.
* Weights are still charged at single-core CPU cost, because every validator must be able to keep
  up, GPU or not.
* Only Apple Metal is implemented. A CUDA backend would slot in behind the same trait, with the same
  differential tests.

Why signatures? ML-DSA verification is mostly SHAKE128 matrix expansion and number-theoretic
transforms: integer-only, embarrassingly parallel, and exactly what makes post-quantum accounts
expensive. That makes it the GPU workload that matters most for this design.

## Quick start

```bash
cargo build --release                       # node + CLI (~10 min cold)
./target/release/canggu-node --dev --tmp    # 2 s blocks, RPC on 127.0.0.1:9944
                                            # add --crypto-backend metal on Apple silicon
./target/release/canggu demo                # in another terminal
```

Requirements: Rust 1.93 (pinned by `rust-toolchain.toml`), `protoc`, clang. A `Dockerfile` based on
Parity's CI image is included but has not been tested yet.

### CLI

Dev keys are ML-DSA-65 keys derived from `//Alice` … `//Eve`, all pre-funded on the dev chain.

```bash
canggu account //Alice
canggu balance //Eve
canggu transfer --from //Dave --to //Eve --amount 1.5 --after //Bob:0   # only after Bob's nonce-0 tx
canggu payroll  --from //Alice --pay //Bob=10 --pay //Charlie=20
canggu zk-setup --recipients 3        # single-party setup: demo only
canggu zk-register --from //Bob
canggu zk-prove --salt 7 --amounts 100,200,300
canggu zk-submit --from //Bob
canggu intents --count 640 --forge 4  # one batch of PQ-signed intents (GPU with --crypto-backend metal)
canggu bench                          # native crypto benchmarks, no node needed
```

### Tests

```bash
cargo test --release --workspace
```

53 tests. Besides the GPU differential tests above, the runtime integration tests
(`runtime/tests/extrinsics.rs`) push real ML-DSA-signed extrinsics
through `Executive`. They cover valid transfers, bit-flipped and key-substituted signatures
(`BadProof`), a DAG child before its parent (`Future`), and tips (rejected).

## Repository layout

| Path | Crate | Role |
| --- | --- | --- |
| `primitives/` | `canggu-primitives` | `CangguSignature`, host functions, dev keyring |
| `pallets/dag-ordering/` | `canggu-dag-ordering` | `CheckDagParents`, `ChargeTransactionPaymentNoTip` |
| `pallets/zk-verifier/` | `pallet-zk-verifier` | Groth16 verifying keys and proofs |
| `pallets/parallel-payroll/` | `pallet-parallel-payroll` | Conflict-free batch payments |
| `pallets/pq-intents/` | `pallet-pq-intents` | Batches of ML-DSA-signed intents, one batch host call |
| `gpu/` | `canggu-gpu` | ML-DSA-65 batch verification on Apple Metal, CPU mirror, differential tests |
| `gpu/bench/` | `canggu-gpu-bench` | Metal vs CPU benchmark |
| `scripts/` | | `mixed-backends.sh`: two validators, GPU vs CPU, one chain |
| `zk/` | `canggu-zk` | Private payroll circuit, setup, proving |
| `runtime/` | `canggu-runtime` | FRAME runtime |
| `node/` | `canggu-node` | Aura + GRANDPA node with Canggu host functions |
| `cli/` | `canggu-cli` | `canggu` wallet, prover, demo, benchmarks |

## Limitations

This is a research prototype:

* Only *account* signatures are post-quantum. Aura/GRANDPA session keys, the p2p handshake and
  Groth16 are still classical.
* Weights are hand-set rather than benchmarked. The trusted setup is single-party and the circuit is
  unaudited.
* The DAG enforces only the dependencies users declare. There is no encrypted mempool yet.

See [TODO.md](TODO.md) for the roadmap.

## License

GPL-3.0, as chosen by the original authors. See [LICENSE](LICENSE).
