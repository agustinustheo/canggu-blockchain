# Sealed ordering against front-running

**Code:** [`pallets/sealed-ordering/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/pallets/sealed-ordering)

## In plain words

To front-run you, someone must (1) see your transaction before it runs and (2) get their own
transaction in ahead of it. Sealed ordering removes the second part:

1. **Commit:** you (or a relayer for you) publish only a 32-byte fingerprint of your transaction,
   plus a deposit. Nobody can tell what it does. If a relayer submits it, nobody can tell who it is
   from either.
2. **Reveal:** in the next two blocks, you publish the transaction itself.
3. **Execute:** at the start of a later block, all revealed transactions from the same commit block
   run in an order that **nobody chose** and that nobody could predict when committing.

Someone who sees your reveal and wants to get ahead of you can only commit in a *later* block, and
later blocks always execute after yours.

```text
$ canggu sealed
  relayer committed 4 opaque 32-byte hashes in block(s) {3}: nobody can tell who pays whom
  Dave revealed in block #4 (index 1)
  Charlie revealed in block #4 (index 2)
  Bob revealed in block #4 (index 3)
  block #6: position 0: Bob (ok)
  block #6: position 1: Dave (ok)
  block #6: position 2: Charlie (ok)
  block #6: Eve never revealed, deposit burned
  ok: execution order = blake2(commitment ‖ commit-block hash), not reveal order
```

## Where the idea comes from

This is adapted from the **Rand Protocol whitepaper** by Dendi Suhubdy (one of Canggu's original
authors) and Anish Mohammed. Its Proposition 14.2 shows that hiding transaction contents is not enough, because the
block producer can still order by metadata. Its Theorem 15.4 shows that front-running is removed
only if three conditions hold:

1. the order is fixed while the contents are still hidden;
2. there is exactly one valid order, and it binds the block producer;
3. what is visible before ordering does not tell transactions apart.

Rand meets condition 1 with *threshold encryption* (validators jointly decrypt after ordering).
Practical threshold encryption today uses elliptic-curve pairings, which are not quantum-safe, and
Rand's live chain does not implement it. Canggu uses **hash commitments** instead, which only need
a hash function.

## How it is built on the Polkadot SDK

The whole feature is one ordinary FRAME pallet with two calls and one hook.

| Step | Pallet item | What happens |
| --- | --- | --- |
| Commit (block N) | `commit(commitment)` | Stores `BLAKE2b("canggu/sealed/v1", sender, call, salt)` and holds a deposit (1 CGU). |
| Reveal (blocks N+1 to N+2) | `reveal(N, call, salt)` | Must come from the sender named in the commitment. Stores the call. |
| Execute (start of block N+3) | `on_initialize` hook | Sorts revealed calls of block N by `BLAKE2b(commitment ‖ hash of block N)` and dispatches them. Returns deposits of revealed commitments; burns the others. |

The hook runs at the start of every block, before normal transactions, so the block producer
cannot place anything in between. The sort key uses the hash of block N, which nobody knows when
they commit in block N.

Limits that keep the hook safe: at most 64 commitments per block, each sealed call at most
1/400 of a slot's time, and only calls of the Balances and Payroll pallets can be sealed.

## What it does not do

> **CAUTION:** Commit-reveal is weaker than threshold encryption in four ways.

- A sender can decline to reveal (a "free option"). The deposit of whoever submitted the
  commitment is burned. If a relayer submitted it, the relayer pays, not the sender: a relayer
  must charge senders for that risk.
- A block producer can refuse to include reveals (censorship).
- The producer of block N can try to influence the hash of block N. That only reshuffles
  commitments whose contents nobody can see.
- **Back-running** (acting right *after* a revealed transaction) is not prevented.

A further idea, not built: commitments could carry a ring proof from the
[`verifiable`](https://github.com/paritytech/verifiable) library, proving "this came from some
registered account" without a relayer. See [Lessons from Rand Protocol](../results/rand-protocol.md#is-verifiable-useful-here).
