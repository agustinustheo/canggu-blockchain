# TODO: Canggu on the Polkadot SDK

The original research checklist from the Bitwyre team, with the status of the Polkadot SDK
rebuild. See the README for details.

## Consensus Mechanisms

- [x] Consensus mechanism: Aura (2 s round-robin leader slots) + GRANDPA finality
- [ ] Post-quantum consensus keys (Aura/GRANDPA are still sr25519/ed25519)
- [ ] Sub-second finality (needs a different finality gadget)

## Quantum Resistant and Canggu Specific Features

- [x] Quantum-resistant crypto: Dilithium (ML-DSA-65, FIPS 204) account signatures
- [ ] Kyber (ML-KEM, FIPS 203): it is a KEM, so it belongs to an encrypted mempool / p2p transport,
      not to transaction signing
- [x] DAG-based mempool: cross-account dependencies enforced by the pool and by consensus
- [ ] Encrypted mempool (needed to stop front-running of independent transactions)
- [x] ZK-SNARKs: proof generation (off-chain) and on-chain Groth16 verification
- [ ] Post-quantum proofs (STARKs); BLS12-381 is not quantum-resistant
- [x] Explore NIST post-quantum crypto papers: Kyber, Dilithium specs

## GPU (originally "CUDA")

- [x] GPU backend for the runtime's crypto host functions: batch ML-DSA-65 on Apple Metal
- [ ] CUDA backend behind the same trait and differential tests
- [ ] GPU-accelerated proof generation (MSM / NTT)
- [ ] Benchmarked weights
