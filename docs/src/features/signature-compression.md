# Signature compression with a zkVM

**Code:** [`pallets/pq-intents/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/pallets/pq-intents),
[`sp1/programs/mldsa-batch`](https://github.com/agustinustheo/canggu-blockchain/tree/main/sp1/programs/mldsa-batch)

## In plain words

Post-quantum signatures are big: 5.3 kB of key and signature per transfer. That size, not CPU
time, limits the chain to about 370 transfers per second.

*Signature compression* replaces many signatures with one proof that says "I checked all of these
signatures, and they are all valid". The chain checks the proof instead of the signatures.

It works. It is also the clearest example in this project of an idea that only pays off at scale.

## Step 1: intent batches

`pallet-pq-intents` lets users sign *intents* off-chain ("pay 1 CGU to Bob, this is my intent
number 3"). A relayer collects up to 640 of them and submits them in one transaction. The runtime
checks all signatures with **one** host call:

```rust
fn ml_dsa_65_batch_verify(items: Vec<(public_key, message, signature)>) -> Vec<bool>;
```

Each intent then succeeds or fails on its own (bad signature, wrong nonce, not enough balance).
This one call is also where a GPU can help: see [GPU verification](gpu.md).

## Step 2: replace the signatures with one SP1 proof

`sp1/programs/mldsa-batch` is a Rust program that verifies ML-DSA-65 signatures. It runs inside the
SP1 zkVM, which produces a proof that the program ran correctly. The program:

1. verifies every signature in the batch (if one is invalid, no proof can be made);
2. outputs a digest: `n ‖ Keccak(context) ‖ Keccak(for each: account ‖ Keccak(message))`, where
   `account = BLAKE2b(public key)`.

`submit_compressed` then takes only `(sender, intent)` pairs and the proof: **no keys and no
signatures**. The runtime rebuilds the digest from the intents and the chain's genesis hash, and
asks the `sp1_v6_verify_compressed` host function whether the proof matches. Because the runtime
computes the digest itself, the proof cannot be reused for other intents or on another chain.

```text
$ canggu intents --count 8 --senders 4 --compressed
mldsa-batch proved: 5611080 cycles, 1272546 byte proof, 112.7 s
  relayer submits 1.28 MB (one SP1 proof, no keys or signatures) instead of 0.04 MB
  block #91: 8 intents executed, 0 rejected {}
```

The ML-DSA code inside SP1 gives the same answer as the `ml-dsa` crate on every test case (4,280
native cases and 460 runs inside the zkVM). SP1's Keccak *precompile* (a built-in accelerator for
the hash function that ML-DSA uses heavily) cuts the cost from 1.83 million to 0.70 million cycles
per signature.

## Step 3: the honest numbers

| | |
| --- | --- |
| One proof, any batch size | 1,272,546 bytes |
| One ML-DSA key and signature | 5,261 bytes |
| **Break-even** | **about 242 signatures per proof** |
| Proving time on the laptop CPU | about 9.4 s per signature (4 signatures: 72 s; 128 signatures: 1,219 s) |
| Time to reach break-even | about 37 minutes |
| Peak memory while proving | 14–17 GB |

So the 8-intent demonstration batch is **30 times bigger** than the signatures it replaces.
Compression only wins with batches of hundreds of signatures, proven on GPUs. SP1's GPU prover
needs NVIDIA (CUDA), which this laptop does not have.

## The bigger design this points to

Rand Protocol (a chain by Dendi Suhubdy) solves the same problem for its own, much larger proofs: GPU
"aggregators" prove one proof over a window of already-finalised blocks, off the critical path, and
are paid for it. That pipeline is what would make compression pay off here too. It is not built.
See [Lessons from Rand Protocol](../results/rand-protocol.md).
