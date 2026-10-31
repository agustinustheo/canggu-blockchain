# All the numbers

Every number below was measured on one Apple M4 Pro laptop (12 CPU cores, 24 GB memory), with
release builds. Other hardware will give different numbers.

## Post-quantum accounts

| Measurement | Value |
| --- | --- |
| ML-DSA-65 public key | 1,952 B |
| ML-DSA-65 signature | 3,309 B |
| Signed transfer | 5,345 B |
| Sign (1 core) | about 0.75 ms |
| Verify (native host function, 1 core) | 61 µs |
| Block capacity (5 MiB blocks, 75 % for normal transactions) | about 735 transfers |
| Throughput (2 s blocks) | about 370 transfers per second, limited by block space |

## GPU batch verification (ML-DSA-65)

| Batch | 1 CPU core | 12 CPU cores | Metal GPU | Metal vs 12 cores |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.060 ms | 0.060 ms | 0.330 ms | 0.18× |
| 64 | 3.77 ms | 0.61 ms | 0.45 ms | 1.35× |
| 256 | 15.2 ms | 1.95 ms | 0.85 ms | 2.29× |
| 1,024 | 61.2 ms | 7.52 ms | 2.12 ms | 3.55× |
| 4,096 | 246 ms | 29.0 ms | 6.51 ms | 4.45× |

Correctness: 5,454 test cases, all three implementations agree.

## Groth16 (BLS12-381) payroll circuit

| Salaries | Constraints | Setup | Prove | Verify | Proof |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 1,917 | 25 ms | 33 ms | 2.5 ms | 192 B |
| 16 | 6,669 | 57 ms | 68 ms | 2.3 ms | 192 B |
| 64 | 25,677 | 176 ms | 185 ms | 2.3 ms | 192 B |
| 256 | 101,709 | 0.60 s | 0.57 s | 2.3 ms | 192 B |
| 1,024 | 405,837 | 2.3 s | 2.0 s | 2.3 ms | 192 B |

An early version of the circuit scaled badly: proving 256 salaries took 119 s. Storing the running
hash as its own variable after each step fixed it (0.57 s).

## SP1 zkVM (CPU prover)

| Measurement | Value |
| --- | --- |
| Compressed proof size (any program, any input) | 1,272,546 B |
| Verification, native | 25.5 ms |
| Verification, through the node's host function | about 40 ms |
| ML-DSA-65 inside SP1, with / without Keccak precompile | 700,713 / 1,833,609 cycles per signature |
| Proving `mldsa-batch`: 4 / 16 / 64 / 128 signatures | 72 s / 204 s / 617 s / 1,219 s |
| Proving `payroll`: 16 / 4,096 / 65,536 / 262,144 salaries | 50 s / 54 s / 141 s / 452 s |
| Peak memory while proving (memory-safe settings) | 14–17 GB |
| Break-even against raw keys and signatures | about 242 signatures per proof |

## Finality (two validators, one computer)

| Block time | Gossip | Vote lag | Median | 90th percentile |
| ---: | ---: | ---: | ---: | ---: |
| 2 s | 333 ms | 2 (default) | 5 s | 6 s |
| 2 s | 50 ms | 0 | 242 ms | 288 ms |
| 500 ms | 50 ms | 0 | 217 ms | 293 ms |
| 500 ms | 25 ms | 0 | 121 ms | 173 ms |

## Tests

| Workspace | Tests |
| --- | --- |
| Main (`cargo test --release --workspace`) | 67 (66 run, 1 ignored: a fixture writer) |
| SP1 host workspace (`sp1/`) | 23 (21 run, 2 ignored: full proofs) |
| SP1 verifier crate | 6 |
