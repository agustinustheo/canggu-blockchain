# Credits and authorship

This project stands on other people's work. This page says exactly whose.

## The idea: Canggu

Canggu, its name, its design and its original whitepaper (v1.3, March 2025) are the work of:

- **Dendi Suhubdy** (Bitwyre)
- **Tejveer Singh** (Bitwyre)
- **Mitul Dhawan** (Bitwyre)
- **Maldini Sonkeng** (Bitwyre)

They published the design and the start of an implementation as open source under the GPL-3.0
license. The first commits of the code repository are theirs (by Dendi Suhubdy and Mitul
Dhawan, [@mitul72](https://github.com/mitul72)). The whitepaper repository's history is theirs (by
Dendi Suhubdy and Maldini Sonkeng). Both histories are kept unchanged in the forks this book links
to. Credit for the idea belongs to them.

This rebuild is not endorsed by them. It changes and corrects parts of their design (see
[What the original design got wrong](results/corrections.md)). Any mistakes in the rebuild are
ours, not theirs.

## The rebuild: who did what

- **Claude**, an AI model made by Anthropic, wrote the code, the tests, the measurements, the
  whitepaper v2.0 and this book. That includes the parts built by separate Claude sessions working
  on sub-tasks (the Metal GPU kernels and the SP1 programs).
- **[agustinustheo](https://github.com/agustinustheo)** started the project, chose the goals,
  pointed to the sources (Canggu, Rand Protocol, SP1, `verifiable`), reviewed the results and
  published them under his GitHub account. In his own words, it is not his work.

The goal was research: to learn how far the Polkadot SDK can be pushed toward a design this
ambitious. It is not a product and has not been audited.

## Ideas we adapted

- **Rand Protocol**, a later blockchain by **Dendi Suhubdy**
  ([full node](https://github.com/randprotocol/fullnode)), described in the whitepaper
  *Randprotocol: Confidential Arbitrary Computations* by **Dendi Suhubdy** (Bitwyre) and **Anish
  Mohammed** (Zeroknowledge Consulting Ltd)
  ([PDF](http://randprotocol.org/papers/randprotocol.pdf)). Sealed ordering adapts its
  corrected front-running theorem (Proposition 14.2 and Theorem 15.4). The signature-compression
  analysis follows its block-aggregation and block-space documents.
- **MiMC** hash design by Martin Albrecht, Lorenzo Grassi, Christian Rechberger, Arnab Roy and Tyge
  Tiessen (used in the demo Groth16 circuit).
- **Groth16** proof system by Jens Groth.
- **CRYSTALS-Dilithium / ML-DSA** by the CRYSTALS team, standardised by NIST as FIPS 204.

## Software we used

| Project | What it does here | Authors |
| --- | --- | --- |
| [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) (stable2609) | The whole blockchain framework: node, runtime, FRAME pallets, transaction pool, Aura, GRANDPA, and the solochain template we started from | Polkadot SDK contributors |
| [`ml-dsa`](https://crates.io/crates/ml-dsa) 0.1.1 | ML-DSA-65 signing and verification (the reference for everything else) | RustCrypto contributors |
| [arkworks](https://arkworks.rs) 0.6 (`ark-groth16`, `ark-bls12-381`, `ark-relations`, …) | Groth16 proofs on BLS12-381 | arkworks contributors |
| [SP1](https://github.com/succinctlabs/sp1) 6.10 (`sp1-sdk`, `sp1-zkvm`, `sp1-verifier`) | The zkVM: proving Rust programs and verifying their proofs | Succinct Labs and contributors |
| [`objc2`](https://github.com/madsmtm/objc2) / `objc2-metal` / `objc2-foundation` | Rust bindings to Apple's Metal GPU API | Mads Marquart and contributors |
| [Metal](https://developer.apple.com/metal/) | The GPU programming interface the kernels run on | Apple |
| [`rayon`](https://github.com/rayon-rs/rayon) | Multi-core CPU verification | rayon contributors |
| [`parity-scale-codec`](https://github.com/paritytech/parity-scale-codec) and [`scale-info`](https://github.com/paritytech/scale-info) | Encoding of every on-chain type | SCALE codec contributors |
| RustCrypto [`keccak`](https://crates.io/crates/keccak) and [`blake2`](https://crates.io/crates/blake2) | Hashing inside the SP1 ML-DSA program | RustCrypto contributors |
| [`bincode`](https://github.com/bincode-org/bincode) | Decoding SP1 proofs in the verifier | bincode contributors |
| [`clap`](https://github.com/clap-rs/clap) and [`ureq`](https://github.com/algesten/ureq) | The `canggu` command line and its RPC calls | clap and ureq contributors |
| [tectonic](https://tectonic-typesetting.github.io) | Building the whitepaper PDF | tectonic contributors |
| [mdBook](https://github.com/rust-lang/mdBook) | This book | Rust project contributors |

We also use `serde`, `serde_json`, `hex`, `anyhow`, `rand`, `jsonrpsee` and, in tests, `sha3` and
`blake2b_simd`. Hundreds of other open-source crates are pulled in through these. They are listed in the
repository's `Cargo.lock` files, and their authors are credited in each crate's own metadata.

## Projects we evaluated

- [`verifiable`](https://github.com/paritytech/verifiable): ring-VRF membership proofs. Evaluated
  for hiding who submits a sealed commitment. Not used in the code (see
  [Lessons from Rand Protocol](results/rand-protocol.md#is-verifiable-useful-here)).

## License

The code is GPL-3.0, the license the original authors chose. See
[`LICENSE`](https://github.com/agustinustheo/canggu-blockchain/blob/main/LICENSE).
