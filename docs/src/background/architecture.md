# The big picture

This page shows how all the parts fit together. Each box links to a chapter that explains it.

```text
 OFF-CHAIN                          NODE (native code)                      RUNTIME (Wasm, on-chain)
 ─────────                          ──────────────────                      ────────────────────────
 canggu CLI (wallet)                Transaction pool                        CangguSignature
  · ML-DSA-65 keys        ──tx──►    · dependency graph (DAG)       ──►      · ML-DSA-65 or classic
  · signs transactions               · tips refused                         CheckDagParents
                                     │                                      ChargeTransactionPaymentNoTip
 Provers                            Aura (leader per 2 s slot)              pallet-sealed-ordering
  · Groth16 (arkworks)    ─proof─►  GRANDPA (finality votes)                pallet-pq-intents
  · SP1 zkVM (canggu-sp1)            │                                      pallet-zk-verifier
                                    Wasm executor ─────────────────────►    pallet-parallel-payroll
                                     │                                            │
                                    Host functions  ◄──── one call ───────────────┘
                                     · ml_dsa_65_verify
                                     · ml_dsa_65_batch_verify ──► CPU (1 core / all cores)
                                     · groth16_bls12_381_verify    or Apple Metal GPU
                                     · sp1_v6_verify_compressed
```

## The one design idea behind everything

**Keep the rules in the runtime, and move the heavy mathematics into host functions.**

- The runtime decides *what* must be checked: "this signature must be valid", "this proof must
  verify for these public values".
- A host function in the node does *the checking*, as fast native code.

This split is why the project works at all:

- **Post-quantum signatures** are slow inside Wasm and fast natively.
  → [Post-quantum accounts](../features/post-quantum-accounts.md)
- **Zero-knowledge verifiers** (arkworks, SP1) are large native libraries. SP1's verifier does not
  even compile for the runtime's Wasm target.
  → [Zero-knowledge proofs](../features/zk-proofs.md)
- **GPUs** can only be used by native code, and only if the answer is bit-for-bit the same as on a
  CPU. A host function has exactly that shape: bytes in, a yes/no answer out.
  → [GPU verification](../features/gpu.md)

## The life of a transaction

1. The **wallet** builds a call (for example, "send 10 CGU to Bob"), adds the transaction
   extensions (nonce, fee, optional parent transactions) and signs it with ML-DSA-65.
2. The **transaction pool** checks it by calling into the runtime. The signature is verified by
   the `ml_dsa_65_verify` host function. `CheckNonce` and `CheckDagParents` declare which
   transactions it depends on. The fee extension refuses tips.
3. The transaction waits until everything it depends on is ready.
4. The current **Aura leader** builds a block from ready transactions, in dependency order.
5. Every validator **re-executes** the block with the same runtime and the same checks. A block
   that breaks a rule, for example by putting a transaction before one of its declared parents, is
   rejected.
6. **GRANDPA** finalises the block.

## Parts that work differently

- **Sealed transactions** are committed as an opaque hash first, revealed later, and executed at
  the start of a later block in an order nobody chose.
  → [Sealed ordering](../features/sealed-ordering.md)
- **Intent batches** carry hundreds of signed transfers in one transaction, so the runtime can
  verify all signatures with one host call (on a GPU, if the node has one), or replace all of them
  with one SP1 proof.
  → [Signature compression](../features/signature-compression.md)
