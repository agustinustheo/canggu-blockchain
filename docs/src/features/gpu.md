# GPU verification with Apple Metal

**Code:** [`gpu/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/gpu),
[`node/src/accel.rs`](https://github.com/agustinustheo/canggu-blockchain/blob/main/node/src/accel.rs),
[`primitives/src/accel.rs`](https://github.com/agustinustheo/canggu-blockchain/blob/main/primitives/src/accel.rs)

## In plain words

The Canggu whitepaper wants smart contracts that run on GPUs. That does not work on a chain whose
execution must be deterministic and metered, for the reasons below. What *does* work is this: when a block contains hundreds of post-quantum
signatures, a validator can check them all on its GPU, while another validator checks the same
signatures on its CPU, and both always agree.

That is what this project does, on the GPU of an Apple M4 Pro laptop through Apple's Metal API.

## Why the runtime itself cannot run on a GPU

- **Every validator must get identical results, bit for bit.** GPU floating-point maths and the
  order of parallel sums vary between GPU models and drivers.
- **Execution must be measured and limited** (weights). A GPU kernel cannot be stopped halfway or
  measured per instruction.
- **The chain's state lives in a database tree** that GPU code cannot reach.
- **Requiring one vendor's GPU** would shut out every validator without one.

## The way that works: a GPU behind a host function

The runtime asks one question per batch: "which of these signatures are valid?" (the
`ml_dsa_65_batch_verify` host function). The answer is a list of yes/no values, and it must be
exactly the same however it is computed. The node chooses how to compute it when it starts:

```text
canggu-node --crypto-backend <cpu | cpu-parallel | metal>

  cpu            reference implementation, 1 core        ← defines the correct answer
  cpu-parallel   reference implementation, all cores     (default)
  metal          ML-DSA-65 verification as Metal compute kernels
                   CPU: decode, checks, hash the key and message, build the challenge
                   GPU: NTTs → expand matrix A and multiply → UseHint → final SHAKE256 compare
```

Batches below 64 signatures go to the CPU, because sending work to the GPU has a fixed cost of
about 0.2 ms.

## How we know it is correct

Correctness matters more than speed here: a GPU that disagreed with the CPU on one signature
would make its validator reject valid blocks.

1. **Three implementations agree.** The Metal kernels, a pure-Rust copy of each kernel, and the
   RustCrypto `ml-dsa` crate were compared on **5,454 cases**: 2,504 valid signatures and 2,950
   damaged ones (flipped bits in every field, bad hints, edge values, wrong lengths and contexts).
   All three gave the same answer every time.
2. **A self-test at start-up.** The node checks the GPU's arithmetic against the CPU (including
   one step for *every* possible input) before it accepts the GPU. During development this test
   caught a deliberately planted bug that real signatures never trigger.
3. **Two validators, two kinds of hardware.** `scripts/mixed-backends.sh` runs Alice on the GPU and
   Bob on one CPU core. They take turns making blocks, so every batch is checked by the GPU on one
   validator and by the CPU on the other:

```text
#6:  authored by Alice (metal), imported by Bob (cpu)
#7:  authored by Bob (cpu), imported by Alice (metal)
#8:  authored by Alice (metal), imported by Bob (cpu)
#9:  authored by Bob (cpu), imported by Alice (metal)
#10: authored by Alice (metal), imported by Bob (cpu)
#11: authored by Bob (cpu), imported by Alice (metal)
blocks 1..11: identical
finalized: alice #11, bob #11
```

## How fast it is

Measured with `cargo run --release --bin bench` (medians, Apple M4 Pro). "GPU busy" is measured by
Metal itself.

| Signatures in batch | 1 CPU core | 12 CPU cores | Metal | GPU busy | Metal vs 12 cores |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.060 ms | 0.060 ms | 0.330 ms | 0.203 ms | 0.18× |
| 64 | 3.77 ms | 0.61 ms | 0.45 ms | 0.23 ms | 1.35× |
| 256 | 15.2 ms | 1.95 ms | 0.85 ms | 0.43 ms | 2.29× |
| 1,024 | 61.2 ms | 7.52 ms | 2.12 ms | 1.50 ms | 3.55× |
| 4,096 | 246 ms | 29.0 ms | 6.51 ms | 5.59 ms | **4.45×** (630,000 signatures/s) |

In a live node, 640 signatures took 8.4 ms with 4.1 ms of GPU time. That is slower than the
benchmark, because the node copies the batch into the host function and, on this machine, a macOS
background service was using the GPU at the same time.

## Limits

- **Fees do not change.** Weights are still charged at single-core CPU speed, because every
  validator must keep up, with or without a GPU. A GPU makes blocks faster to process; it does not
  raise the chain's limits.
- **Apple Metal only.** An NVIDIA (CUDA) backend would plug into the same interface, with the same
  tests. It is not written.
- **Small batches lose.** Below about 64 signatures the CPU is faster.
