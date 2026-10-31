# Canggu on the Polkadot SDK

> ## ⚠️ 🚧 For learning only. Use at your own peril. 🚧 ⚠️
>
> This is a research prototype that explores how far the Polkadot SDK can go. It is not audited
> and it is not production software. Do not use it, or its development keys, to hold or move real
> value.

**How far can the Polkadot SDK go?**

This book documents an experiment. We took *Canggu*, an ambitious blockchain design, and tried to
build it on the [Polkadot SDK](https://github.com/paritytech/polkadot-sdk), the Rust framework that
includes Substrate and FRAME. Canggu asks for things that sound like years of work:

- accounts that stay safe when large quantum computers arrive;
- zero-knowledge proofs, including proofs from a **zkVM** (a virtual machine that proves it ran a
  program correctly);
- protection against front-running (*MEV*);
- smart-contract-style work on **GPUs**;
- finality in under a second.

The result is a working chain. It produces blocks, verifies post-quantum signatures, checks
zkVM proofs on-chain, verifies batches of signatures on an Apple GPU, and keeps two validators
in consensus while one uses a GPU and the other a CPU. Every performance number of this project in this book
was measured on a real machine (an Apple M4 Pro laptop); numbers quoted from other projects are
marked as such. Every limitation we found is written down.

> **This is not our idea.** Canggu was designed by **Dendi Suhubdy, Tejveer Singh, Mitul Dhawan
> and Maldini Sonkeng** (Bitwyre), who wrote the original whitepaper and open-sourced it. This
> rebuild was written by **Claude**, an AI model made by Anthropic, in a conversation directed by
> [agustinustheo](https://github.com/agustinustheo), who published it. See
> [Credits and authorship](credits.md) for every person and library this work stands on.

## Who this book is for

You do not need to know blockchains, cryptography or Rust to read most of it. Each chapter starts
in plain words and only then goes into detail. If a word is new, look it up in the
[Glossary](appendix/glossary.md).

- **New to all of this?** Read [What Canggu set out to do](background/canggu-v1.md), then
  [The Polkadot SDK in ten minutes](background/polkadot-sdk-primer.md) and
  [The big picture](background/architecture.md).
- **Want to run it?** Go to [Build and start a chain](getting-started/build-and-run.md).
- **Want the conclusions?** Read [Why the Polkadot SDK made this possible](results/why-polkadot-sdk.md)
  and [Limitations and open problems](results/limitations.md).

## What is in the box

| Canggu idea | How it was built here | Status |
| --- | --- | --- |
| Quantum-safe accounts (Dilithium) | A new account signature type (ML-DSA-65) checked by native node code | Works |
| Transactions that cannot be reordered past their dependencies | The transaction pool's existing dependency graph, plus one extension | Works |
| Front-running protection | No tips, and *sealed ordering*: commit now, reveal later, run in an order nobody chose | Works, with known trade-offs |
| Zero-knowledge proofs | Groth16 (small, not quantum-safe) and **SP1 zkVM** proofs (large, quantum-safe) | Works |
| Signature compression | One SP1 proof replaces every signature in a batch | Works, but only pays off with large batches and GPU provers |
| GPU acceleration | Batch signature verification on Apple Metal, behind a node function | Works |
| Fast leader-based consensus | Aura block production and GRANDPA finality | Works |
| Sub-second finality | GRANDPA with two settings changed: 242 ms with 2 s blocks, 121 ms with 500 ms blocks, on one machine | Works on localhost; not tested over a real network |
| 50,000+ transactions per second | Not reached: about 370 per second, limited by signature size | Not possible as designed |

## Where things live

- The code: [github.com/agustinustheo/canggu-blockchain](https://github.com/agustinustheo/canggu-blockchain)
- The original whitepaper (v1.3) and the Polkadot SDK edition (v2.0):
  [github.com/agustinustheo/canggu-blockchain-whitepaper](https://github.com/agustinustheo/canggu-blockchain-whitepaper)
- This book's source: the [`docs/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/docs)
  folder of the code repository.
