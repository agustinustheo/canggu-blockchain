# Transactions that wait for each other

**Code:** [`pallets/dag-ordering/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/pallets/dag-ordering)

## In plain words

Canggu's whitepaper wants a **DAG mempool**: a transaction can say "I depend on that other
transaction", and nobody can put it before that other transaction. Here, any transaction can name
up to eight *parent* transactions, including other people's. The chain guarantees that a
transaction never runs before its parents.

The demonstration shows it. Charlie's transaction names Bob's transaction as its parent, and
Charlie's is sent first:

```text
  submitting Charlie's tx FIRST; it declares Bob's tx (nonce 0) as parent
  2 blocks later the child is still not in any block: it waits for its parent
  now submitting Bob's parent tx
  parent: block #6 index 1 | child: block #6 index 2
  ok: the child executed strictly after its parent
```

## How it is built on the Polkadot SDK

### The pool is already a DAG

The Polkadot SDK transaction pool does not use a simple queue. Each transaction declares tags it
**provides** and tags it **requires**, and it becomes *ready* only when everything it requires is
provided. Normally the tags are `(account, nonce)`: your transaction with nonce 5 provides
`(you, 5)` and requires `(you, 4)`. So every chain built with the Polkadot SDK already has a
dependency graph. It just only links an account to itself.

### One extension adds cross-account edges

`CheckDagParents` is a *transaction extension*. A transaction lists parents as `(account, nonce)`
pairs. The extension does two things:

1. **In the pool:** for each parent that has not executed yet, add a `requires` tag. The tag has
   exactly the encoding that the standard `CheckNonce` extension uses for `provides`. So the pool,
   unchanged, waits for the parent.
2. **When the block executes:** check again that every parent has executed (its account's nonce
   has moved past the parent's nonce). If not, the transaction is invalid. A block producer that
   puts a child before its parent produces an **invalid block**, which every honest validator
   rejects.

The check runs *before* `CheckNonce`. That way a rejected transaction changes nothing, not even the
sender's nonce. (An early version had them the other way round; a test caught it.)

## No tips, no priority auction

In a standard Polkadot SDK chain, a higher **tip** gives a transaction a higher priority. That makes
tips an open auction for position, which is exactly what front-runners pay for.

`ChargeTransactionPaymentNoTip` is the standard fee extension with one change: any tip is refused.
It keeps the same name and encoding, so wallets keep working as long as they send a tip of zero.

```text
  rejected by the pool as expected: Invalid Transaction: "Custom error: 0"
```

## Limits

- **It only enforces declared dependencies.** A transaction that names no parent can still be
  front-run by any transaction that does not depend on it. The whitepaper claimed that a DAG makes
  front-running "computationally infeasible"; that is not true (see
  [What the original design got wrong](../results/corrections.md)). The fix for undeclared
  front-running is [sealed ordering](sealed-ordering.md).
- **Eight parents at most**, to keep the check cheap.
