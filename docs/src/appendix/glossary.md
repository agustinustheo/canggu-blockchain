# Glossary

**Aura**: The Polkadot SDK's block-production method. Validators take turns, one per time slot.

**BLAKE2b**: The hash function Polkadot SDK chains use. Canggu derives account addresses from ML-DSA public keys with it.

**BLS12-381**: An elliptic curve used by Groth16 proofs. It is not safe against quantum computers.

**Commitment**: A hash that fixes a value without showing it. Sealed ordering uses commitments to fix the order before contents are known.

**CUDA**: NVIDIA's GPU programming system. Not used here; the Metal backend is Apple's equivalent.

**DAG (directed acyclic graph)**: A set of items with "comes after" arrows and no loops. Transactions with dependencies form one.

**Deterministic**: Always giving the same output for the same input. Runtimes must be deterministic so every validator agrees.

**Extrinsic**: The Polkadot SDK's word for a transaction (or other data put into a block from outside).

**Finality**: The point after which a block can never be undone.

**FRAME**: The Polkadot SDK's framework for building runtimes out of pallets.

**GRANDPA**: The Polkadot SDK's finality protocol. Validators vote; a block with votes from more than two-thirds of them is final.

**Groth16**: A zero-knowledge proof system with very small proofs (192 bytes) and a trusted setup. Not quantum-safe.

**Host function**: A function the node provides to the runtime. The runtime calls it; the node runs it as native code.

**Intent**: In Canggu, a transfer signed off-chain and submitted in a batch by a relayer.

**Keccak / SHAKE**: A family of hash functions. ML-DSA uses SHAKE heavily; SP1 has a fast built-in (precompile) for it.

**MEV (maximal extractable value)**: Profit a block producer can make by choosing, adding or reordering transactions, for example front-running.

**Metal**: Apple's GPU programming interface.

**ML-DSA (FIPS 204)**: The NIST post-quantum signature standard, formerly CRYSTALS-Dilithium. Canggu uses the ML-DSA-65 parameter set.

**ML-KEM (FIPS 203)**: The NIST post-quantum key-exchange standard, formerly CRYSTALS-Kyber. It cannot sign.

**Nonce**: A counter per account. Each transaction uses the next number, so it cannot be replayed.

**Pallet**: A module of a FRAME runtime, with its own storage, calls and events.

**Parachain**: A chain that gets its security from Polkadot's relay chain. Canggu is not one; it is a standalone chain.

**Post-quantum**: Believed to stay secure against large quantum computers.

**Precompile**: A built-in, accelerated operation in a virtual machine (here, Keccak in SP1).

**Relayer**: Someone who submits other people's signed data (intents, commitments) and pays the fee.

**Runtime**: The chain's rules, compiled to WebAssembly and stored on-chain.

**Shor's algorithm**: A quantum algorithm that breaks the elliptic-curve and factoring problems behind today's signatures.

**SP1**: A zkVM by Succinct Labs that proves Rust programs compiled to RISC-V.

**STARK**: A family of proof systems that use only hash functions. No trusted setup; plausibly post-quantum; large proofs.

**Transaction extension**: A check that runs before and after every transaction (nonce, fee, mortality (era), and Canggu's dependency check).

**Weight**: The Polkadot SDK's measure of execution time. Blocks have a weight limit; fees follow weight.

**zkVM**: A zero-knowledge virtual machine: it proves that a normal program ran correctly. 
