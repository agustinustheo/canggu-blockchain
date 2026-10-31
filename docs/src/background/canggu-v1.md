# What Canggu set out to do

*Canggu* is a blockchain design published in March 2025 by Dendi Suhubdy, Tejveer Singh, Mitul
Dhawan and Maldini Sonkeng (Bitwyre) in the whitepaper *"Canggu Blockchain: A Quantum-Secure,
MEV-Resistant Blockchain for Parallel Computing"* (v1.3). This page summarises their goals. Later
chapters show how each one was built, and where the design had to change.

## The four problems it targets

1. **Quantum computers.** The signatures that protect almost every blockchain account today
   (ECDSA, Ed25519, Sr25519) can be broken by a large enough quantum computer running Shor's
   algorithm. Canggu wants accounts that stay safe.
2. **Front-running (MEV).** Whoever builds a block chooses the order of its transactions. They can
   put their own trade just before yours and profit from it. Canggu wants ordering that block
   producers cannot exploit.
3. **Sequential execution.** Most chains run transactions one at a time on one CPU core, even when
   the transactions do not touch the same data. Canggu wants to use parallel hardware, including
   GPUs.
4. **Slow or fragile consensus.** Canggu wants fast block production with a rotating leader and
   finality in under a second.

## The five building blocks it proposes

| Building block (v1.3) | In plain words |
| --- | --- |
| CRYSTALS-Dilithium signatures, Kyber key exchange, XMSS hashing | Use the new NIST post-quantum algorithms everywhere |
| A DAG-based mempool | Transactions point at the transactions they depend on, so they cannot be reordered past them |
| Leader-based BFT consensus (like Solana's Tower BFT) | One leader at a time proposes blocks; a vote finalises them |
| ZK-SNARKs for verifiers and provers | Expensive work is proven once, and everyone else checks a small proof |
| Parallel smart contracts on CPU and GPU | Contracts can include GPU code (CUDA) for data-parallel work |

The whitepaper also targets **50,000+ transactions per second**.

## What this rebuild found

Most of the design could be built, sometimes much more easily than expected. Several claims did
not survive contact with real code and measurements: for example, Kyber cannot sign
transactions, BLS12-381 proofs are not quantum-safe, and 50,000 transactions per second does not
fit with post-quantum signature sizes. Those findings are not criticism of the authors' ambition;
they are what an implementation is for. See [What the original design got wrong](../results/corrections.md).

The original whitepaper is kept unchanged at
[`canggu-blockchain-whitepaper`](https://github.com/agustinustheo/canggu-blockchain-whitepaper)
(`main.tex` and `Canggu_Blockchain_Whitepaper_v1_3.pdf`). The Polkadot SDK edition (v2.0), which
describes this code, is in the same repository under `v2/`.
