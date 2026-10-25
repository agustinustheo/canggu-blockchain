# TODO: Canggu on the Polkadot SDK

The original research checklist from the Bitwyre team, with the status of the Polkadot SDK
rebuild. See the README for details.

## Consensus Mechanisms

- [x] Consensus mechanism: Aura (2 s round-robin leader slots) + GRANDPA finality
- [ ] Post-quantum consensus keys (Aura/GRANDPA are still sr25519/ed25519)
- [x] Sub-second finality on localhost by tuning GRANDPA (vote lag 0, short gossip): 242 ms p50
- [ ] Measure finality over a real network (WAN latency between validators)

## Quantum Resistant and Canggu Specific Features

- [x] Quantum-resistant crypto: Dilithium (ML-DSA-65, FIPS 204) account signatures
- [ ] Kyber (ML-KEM, FIPS 203): it is a KEM, so it belongs to an encrypted mempool / p2p transport,
      not to transaction signing
- [x] DAG-based mempool: cross-account dependencies enforced by the pool and by consensus
- [x] Order-then-reveal (sealed) ordering against front-running, adapted from Rand Protocol's
      Theorem 15.4 with hash commitments
- [ ] Threshold-encrypted mempool (removes the commit-reveal free option; needs post-quantum
      threshold decryption)
- [ ] Anonymous commitments via ring proofs (`paritytech/verifiable`) instead of relayers
- [x] Signature compression: one SP1 proof per intent batch (works; breaks even at ~242 sigs)
- [ ] Windowed aggregation by a GPU prover market (Rand Protocol's design), CUDA provers
- [x] ZK-SNARKs: proof generation (off-chain) and on-chain Groth16 verification
- [x] Post-quantum proofs: SP1 compressed STARKs next to Groth16
- [x] Explore NIST post-quantum crypto papers: Kyber, Dilithium specs

## GPU (originally "CUDA")

- [x] GPU backend for the runtime's crypto host functions: batch ML-DSA-65 on Apple Metal
- [ ] CUDA backend behind the same trait and differential tests
- [ ] GPU-accelerated proof generation (MSM / NTT)
- [ ] Benchmarked weights
