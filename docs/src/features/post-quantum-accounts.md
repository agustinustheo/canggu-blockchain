# Post-quantum accounts

**Code:** [`primitives/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/primitives)

## In plain words

Every Canggu account is controlled by an **ML-DSA-65** key (the NIST standard formerly called
CRYSTALS-Dilithium). A large quantum computer could forge today's blockchain signatures, but it is
not known to be able to forge these.

The price is size: every transaction carries a 1,952-byte public key and a 3,309-byte signature. A
simple transfer is **5,345 bytes**, against about 150 bytes on a chain with classic signatures.

## How it is built on the Polkadot SDK

### A new signature type

In a Polkadot SDK runtime, the signature type is a type parameter. The standard one,
`MultiSignature`, knows Ed25519, Sr25519 and ECDSA. Canggu defines its own:

```rust
pub enum CangguSignature {
    Ed25519(ed25519::Signature),        // index 0: transition period only
    Sr25519(sr25519::Signature),        // index 1: transition period only
    Ecdsa(ecdsa::Signature),            // index 2: transition period only
    MlDsa65 { public: MlDsa65Public, signature: MlDsa65Signature }, // index 3
}
```

The rest of the chain does not care what is inside, as long as the type can answer one question:
*is this a valid signature of this message by this account?*

### Why the key travels with the signature

Polkadot SDK accounts are 32 bytes (`AccountId32`). An ML-DSA public key is 1,952 bytes, so it
cannot *be* the account. Instead:

```text
account = BLAKE2b-256(ML-DSA public key)
```

and every ML-DSA signature carries its public key. Verification does two things, cheapest first:

1. Hash the public key and check that it equals the sender's account. This stops anyone from
   attaching a different key.
2. Verify the ML-DSA signature.

Signatures use the FIPS 204 *context string* `canggu/tx/v1`, so a signature made for Canggu
cannot be reused anywhere else. Replay across chains and runtime versions is stopped by the
standard Polkadot SDK signed payload (it includes the genesis hash and runtime version).

### Verification runs in the node, not in Wasm

The runtime does not contain the lattice mathematics. It calls a host function:

```rust
#[runtime_interface]
pub trait CangguCrypto {
    fn ml_dsa_65_verify(public: &[u8], msg: &[u8], signature: &[u8]) -> bool;
    // ...
}
```

The node implements it with the RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) crate.
This is exactly how Polkadot SDK chains already verify Sr25519 signatures. One verification takes
**61 µs** on one core of an Apple M4 Pro.

### A transition period

The classic signature types stay available, with the same encoding positions as
`MultiSignature`. That keeps existing tools working while people move to ML-DSA keys. A runtime
upgrade can remove them later.

## What we measured

| | |
| --- | --- |
| Public key / signature | 1,952 B / 3,309 B |
| Signed transfer | 5,345 B |
| Sign (one core) | about 0.75 ms |
| Verify (one core, native host function) | 61 µs |
| Transfers per block (5 MiB blocks, 75 % for normal transactions) | about 735 |
| Transfers per second (2 s blocks) | about 370 |

## Limits

- **Size is the bottleneck.** At about 370 transfers per second the chain runs out of block space,
  not CPU time. See [Signature compression](signature-compression.md).
- **Only accounts are post-quantum.** Block producers (Aura, Sr25519) and finality voters (GRANDPA,
  Ed25519) still sign with classic keys, and so does the peer-to-peer handshake. A quantum attacker
  could forge blocks or votes even though user funds are safe. Changing this needs keystore and
  consensus changes in the node.
- **Development keys only.** `//Alice` and the other dev keys are derived with a simple hash, not
  a real key-derivation scheme.
