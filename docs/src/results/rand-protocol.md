# Lessons from Rand Protocol

[Rand Protocol](https://github.com/randprotocol/fullnode) is a later blockchain by **Dendi
Suhubdy**, one of Canggu's original authors. Its whitepaper,
[*Randprotocol: Confidential Arbitrary Computations*](http://randprotocol.org/papers/randprotocol.pdf),
is by **Dendi Suhubdy and Anish Mohammed**. It makes many of the same choices (Dilithium, STARK
proofs, GPU provers) on a different foundation. Comparing the two explains a lot about both.

## One decision explains most differences

Rand is a **fully shielded** chain: no accounts, no balances, no visible senders. Canggu, like
every Polkadot SDK chain, is an **account** chain.

| | Rand Protocol | Canggu on the Polkadot SDK | Why |
| --- | --- | --- | --- |
| Authorising a transfer | No signature. A STARK proof shows "I own these notes". | One ML-DSA-65 signature per transaction. | A signature names the signer, which a privacy chain cannot allow. On an account chain the sender is public anyway, and a signature is about 250× smaller (5.3 kB vs about 1.3 MB) and about 130,000× faster to make (0.75 ms vs about 100 s). |
| Cost per transfer | About 1.3 MB; about 3 transfers per 4 MiB block | 5.3 kB; about 740 per block | Rand pays for privacy and for strong STARK soundness in bytes. |
| What gets compressed | Proofs: GPU aggregators make one recursive proof over a window of finalised blocks ("sealing"). | Signatures, per intent batch, with one SP1 proof. | At 1.3 MB per transfer Rand *must* aggregate. At 5.3 kB Canggu only gains above about 242 signatures. |
| Old history | Rand chose to aggregate proofs rather than simply drop them, so that a new node checks proofs instead of trusting old finality signatures (it prunes other history in other ways). | The Polkadot SDK already trusts finality proofs for fast sync, so pruning old blocks fits its model. | Different trust models. |
| Where the GPU is | In a separate, paid aggregator market. Validators use CPUs only. | Optional, behind a host function, on validators. | Both keep GPUs out of what consensus requires. |
| Consensus signatures | HotStuff with Dilithium2 votes: post-quantum throughout. | Aura (Sr25519) and GRANDPA (Ed25519): classic. | Rand wrote its own consensus. Changing these in the Polkadot SDK is a larger node change. |
| Proof system | Plonky3 STARKs | Groth16, plus SP1 STARKs | Both end at hash-based STARKs of about 1.3 MB. |
| Front-running | Contents hidden, but the leader still orders by fee. The paper proves front-running is removed only under three conditions, which its live chain does not meet. | DAG dependencies, no tips, and sealed ordering. | The theorem transfers to an account chain. |

## What we took

1. **The corrected front-running theorem** (Proposition 14.2 and Theorem 15.4), adapted with hash
   commitments instead of threshold encryption. See [Sealed ordering](../features/sealed-ordering.md).
2. **The signature-compression analysis.** Rand's documents give the architecture (pipelined
   aggregation over finalised blocks, a GPU prover market, "the proof that covers the most wins",
   proofs bound to their maker) and its price: 26 minutes to prove an aggregate of one transfer in
   a test setup, and at least 512 GB of memory for a production proof. Canggu built the core (one
   SP1 proof per batch) and measured the same lesson. See
   [Signature compression](../features/signature-compression.md).

## Is `verifiable` useful here?

[`verifiable`](https://github.com/paritytech/verifiable) proves *"I am one of these registered
members"* without saying which one. It uses ring VRFs on the Bandersnatch curve, with 752-byte
proofs and one unlinkable 32-byte alias per member per context.

- **Useful for front-running metadata.** A sealed commitment could carry a ring proof that it came
  from some registered account, with one alias per epoch as a rate limit, instead of going through
  a relayer.
- **Not useful for signature compression.** It provides anonymity, not aggregation; its proofs
  are larger than a plain signature and do not combine.
- **Not post-quantum.** Its security rests on elliptic curves. Its interface, though, could front a
  post-quantum implementation (for example a STARK over a Merkle tree with nullifiers, which is how
  Rand's shielded pool works).

It was evaluated but not used in the code.
