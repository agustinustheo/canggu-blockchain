# What the original design got wrong

Building a design is the fastest way to test it. These are the claims from the Canggu v1.3
whitepaper that did not hold up. They are listed so that readers do not repeat them, not to take
anything away from the authors' ambition.

| v1.3 says | What is actually true | What this rebuild does |
| --- | --- | --- |
| Users generate key pairs with **Kyber** for wallet operations. | Kyber (ML-KEM) is a key-exchange scheme. It cannot sign anything. | Accounts use ML-DSA-65 (Dilithium). |
| Transactions are hashed with **XMSS**. | XMSS is a *signature* scheme, and a stateful one (reusing a state breaks it). | Hashing uses BLAKE2b-256, which keeps about 128 bits of security against quantum computers. |
| ZK-SNARKs on **"quantum-resistant curves (e.g., BLS12-381 with NIST-approved tweaks)"**. | No such curve exists. Pairing-based proofs like Groth16 on BLS12-381 are broken by Shor's algorithm. | Keeps Groth16 for comparison, and adds quantum-safe SP1 STARK proofs. |
| A **DAG mempool makes MEV computationally infeasible** (reordering costs Ω(n²)). | Sorting a DAG takes linear time, and any valid order is a valid block. A producer has *more* freedom, not less. | The DAG enforces the dependencies users declare. Front-running is handled separately by sealed ordering. |
| ZK verification is **O(1)**. | Groth16 verification grows with the number of public inputs, though not with circuit size. | No change; just stated correctly. |
| **Solana** executes transactions sequentially in one thread. | Solana's runtime runs non-conflicting transactions in parallel. | The payroll pallet guarantees non-conflicting credits, the same property. |
| **10,000 stablecoin transfers in under 1 ms** on a GPU. | The work is updating 10,000 database entries, not adding numbers. A GPU does not help with that. | The GPU is used for signature verification instead, where it does help. |
| **Sub-second finality** with a Tower-BFT-style design. | Possible with GRANDPA once two defaults are changed (measured on one computer: 242 ms with 2 s blocks, 121 ms with 500 ms blocks). | Two node options; network latency still to be measured. |
| **50,000+ transactions per second** with Dilithium signatures. | At 5.3 kB per transfer that is about 265 MB/s of data. Measured capacity is about 370 transfers per second. | Signature compression with SP1 shows the way, but needs GPU provers and large batches. |
