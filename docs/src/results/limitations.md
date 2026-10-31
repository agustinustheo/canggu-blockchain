# Limitations and open problems

> **WARNING:** This is a research prototype. It is not audited. Do not use it to hold or move real
> value.

## Security

- **Only accounts are post-quantum.** Block production (Aura, Sr25519), finality votes (GRANDPA,
  Ed25519) and the peer-to-peer handshake still use classic cryptography. A quantum attacker could
  forge blocks or votes.
- **The Groth16 path is not post-quantum** and uses a single-party trusted setup (demonstration
  only). The SP1 path is the quantum-safe one.
- **Weights are estimates.** No pallet has benchmarked weights, so fees and block limits are
  approximate.
- **Nothing is audited:** not the pallets, not the GPU kernels, not the SP1 programs, not the MiMC
  circuit.

## Front-running

- Sealed ordering uses commit-reveal, not threshold encryption. Senders can refuse to reveal (the
  committer's deposit is burned; with a relayer, the relayer loses it), block producers can censor
  reveals, and back-running is not prevented.
- Dependency ordering only protects transactions that declare their parents.

## Performance and scale

- About **370 transfers per second**, limited by the size of post-quantum signatures.
- **Signature compression is a net loss** below about 242 signatures per proof, and proving that
  many takes about 37 minutes on a laptop CPU. A GPU prover market is not built.
- **The GPU backend is Apple Metal only.** There is no NVIDIA backend.
- **Finality was measured on one computer only.** Real network delay was not tested.

## Testing

- Everything was built and measured on one Apple M4 Pro laptop. Linux builds and the `Dockerfile`
  are not tested.
- The CI workflow in the repository is from the original project. It runs only on pull requests and
  does not match the current code.

## Open problems worth working on

1. Post-quantum session keys for Aura and GRANDPA.
2. Threshold-encrypted mempool (needs post-quantum threshold decryption, an open research topic).
3. Anonymous sealed commitments with ring proofs.
4. GPU provers and windowed proof aggregation, following Rand Protocol's design.
5. Benchmarked weights, and finality measured over a real network.
