# Zero-knowledge proofs: Groth16 and SP1

**Code:** [`pallets/zk-verifier/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/pallets/zk-verifier),
[`zk/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/zk),
[`sp1/programs/payroll`](https://github.com/agustinustheo/canggu-blockchain/tree/main/sp1/programs/payroll)

## In plain words

An employer wants to prove to the chain: "the salaries I am about to pay add up to this total, and
they match the salary table I committed to earlier", **without showing any salary**. That is a
zero-knowledge proof. The proof is made off-chain. The chain only checks it.

Canggu checks two kinds of proof:

| | Groth16 (original design) | SP1 zkVM (added later) |
| --- | --- | --- |
| How the statement is written | A hand-built arithmetic circuit (arkworks) | A normal Rust function, run in the SP1 zkVM |
| Proof size | 192 bytes | 1,272,546 bytes |
| Check on-chain | about 2.3 ms | about 25 ms (about 40 ms in the node) |
| Trusted setup | Yes (single-party here: demo only) | No |
| Quantum-safe | **No** (elliptic-curve pairings) | **Plausibly yes** (hash-based STARK) |

## How it is built on the Polkadot SDK

`pallet-zk-verifier` does not know any particular circuit. It accepts:

- `register_verifying_key` and `submit_proof` for Groth16 proofs on BLS12-381;
- `submit_sp1_proof(program, public_values, proof)` for SP1 proofs, where `program` is the SP1
  program's 32-byte verification-key hash.

A proof that checks out is recorded as a *statement* (which program, which public values), so
other pallets or apps can rely on it. A failed proof still pays its full fee.

Both checks are host functions, like signature verification:

```rust
fn groth16_bls12_381_verify(vk: &[u8], inputs: &[u8], proof: &[u8]) -> bool;
fn sp1_v6_verify_compressed(proof: &[u8], public_values: &[u8], vkey_hash: &[u8]) -> bool;
```

For SP1 this is not only about speed: SP1's verifier does not compile for `wasm32v1-none`, the
target Polkadot SDK runtimes use. A host function is the only way to use it.

## The payroll statement

Private inputs: a salt and N salaries. Public outputs: the total and a commitment to the salt and
salaries. The two versions differ in detail:

- **Groth16 version** (`zk/`): the salt is one field element, N is fixed when the keys are made,
  and the public inputs are `[total, commitment]`. The circuit has a MiMC hash commitment and a
  64-bit range check per salary: 396 × N + 333 constraints (1,917 for 4 salaries). Proving 1,024 salaries takes 2.0 s on
  12 cores.
- **SP1 version** (`sp1/programs/payroll`): the salt is 32 bytes and the public output is
  `N ‖ total ‖ commitment` (52 bytes). The program is about 25 lines of Rust that sum the salaries
  with overflow checks and commit with Keccak. It needs no circuit design at all. Proving takes about 50
  seconds for 16 salaries and 452 seconds for 262,144 salaries.

```text
$ canggu zk-sp1 --from //Alice --salt "october payroll" --amounts 3000,4500,1250,8000,2200
payroll proved: 6137 cycles, 1272546 byte proof, 59.2 s
  submitting a 1.28 MB post-quantum proof
  ok: the chain verified that 5 private salaries sum to 18950
node: 🔐 SP1 compressed proof (1272546 bytes): valid in 41.95ms
```

## A finding: one proof, many encodings

SP1's standard verifier accepts several different byte strings for the same valid proof. It
ignores extra bytes at the end, and it silently reduces numbers that are too large for the field.
That is harmless for "is this proof valid?", but a chain that stores, hashes or deduplicates proofs
could be confused. Canggu's wrapper (`canggu-sp1-verify`) accepts only the exact canonical bytes. A
test shows both the problem and the fix.

## Limits

- The Groth16 path is **not quantum-safe** and uses a single-party trusted setup. It is kept for
  comparison.
- SP1 proofs are **1.27 MB**: only a few fit in a block.
- Weights are estimates, not benchmarks.
