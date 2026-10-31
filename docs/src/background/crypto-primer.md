# Post-quantum cryptography and zero knowledge, briefly

Two kinds of cryptography appear everywhere in this book. You do not need the mathematics; you
need to know what each one promises and what it costs.

## Post-quantum signatures

A **digital signature** proves that the owner of a private key approved a message. Today's
blockchain signatures (ECDSA, Ed25519, Sr25519) rest on elliptic-curve problems. A large quantum
computer running **Shor's algorithm** would solve those problems and forge signatures.

In 2024 NIST standardised replacements that are believed to resist quantum computers:

| Standard | Old name | What it is | Used in Canggu |
| --- | --- | --- | --- |
| FIPS 204, **ML-DSA** | CRYSTALS-Dilithium | Signature scheme (lattice-based) | Yes: ML-DSA-65 for every account |
| FIPS 203, ML-KEM | CRYSTALS-Kyber | *Key exchange*, not a signature | No (it cannot sign transactions) |
| FIPS 205, SLH-DSA | SPHINCS+ | Signature scheme (hash-based) | No (a conservative alternative) |

The cost is size. An ML-DSA-65 public key is **1,952 bytes** and a signature **3,309 bytes**. A
classic Sr25519 public key and signature are 32 and 64 bytes. That size difference drives several
results in this book.

**Hash functions** (like BLAKE2b, which Polkadot SDK chains use) are much less affected: a quantum
computer only halves their security, so a 256-bit hash keeps about 128 bits of security. That is
enough.

## Zero-knowledge proofs

A **zero-knowledge proof** lets someone prove a statement is true without revealing why. For
example: "these 16 salaries, which I will not show you, add up to 50,000". Two properties matter
for blockchains:

- **Succinct:** checking the proof is fast and small, no matter how much work it proves.
- **Zero knowledge:** the proof reveals nothing beyond the statement.

Making the proof (*proving*) is slow and expensive. Checking it (*verifying*) is fast. That
asymmetry is the whole point: one machine proves, every validator verifies.

### Two families of proof systems

| | Groth16 (a SNARK) | STARKs (e.g. SP1's proofs) |
| --- | --- | --- |
| Proof size | 192 bytes | about 1.27 MB (SP1) |
| Verification | about 2.3 ms | about 25 ms (SP1) |
| Trusted setup | Yes, per circuit | No |
| Quantum-safe | **No**: it uses elliptic-curve pairings, which Shor's algorithm breaks | **Plausibly yes**: it uses only hash functions |

### What a zkVM adds

Writing a proof "circuit" by hand is hard. A **zkVM** (zero-knowledge virtual machine) proves that
an ordinary program ran correctly. [SP1](https://github.com/succinctlabs/sp1), the zkVM used
here, proves Rust programs compiled to RISC-V. In Canggu, SP1 proves two programs:

- a payroll check (the quantum-safe version of the Groth16 demo), and
- a program that verifies a whole batch of ML-DSA signatures, so the chain can accept the proof
  instead of the signatures (*signature compression*).

The Canggu chain does not run a zkVM itself. It **verifies zkVM proofs** that are made off-chain.
