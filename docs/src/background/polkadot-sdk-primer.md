# The Polkadot SDK in ten minutes

The [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) is a toolkit for building
blockchains in Rust. You do not have to use it to join Polkadot: Canggu uses it to build a
**standalone chain** (a *solochain*) with its own validators. This page explains the handful of
ideas you need for the rest of the book.

## 1. A chain is two programs: the node and the runtime

```text
  ┌──────────────────────── canggu-node (native program) ────────────────────────┐
  │  networking · transaction pool · block production · finality · database      │
  │                                                                              │
  │     ┌──────────── canggu-runtime (WebAssembly, stored on-chain) ─────────┐   │
  │     │  the rules: accounts, balances, fees, every "pallet"               │   │
  │     └────────────────────────────────────────────────────────────────────┘   │
  │        ▲ the runtime can only reach the outside world through               │
  │        └ "host functions" that the node provides                            │
  └──────────────────────────────────────────────────────────────────────────────┘
```

- The **node** is an ordinary program. It talks to other nodes, keeps the database, and decides
  when to produce and finalise blocks.
- The **runtime** holds the chain's rules: what a valid transaction is, how balances change, what
  each feature does. It is compiled to WebAssembly (Wasm) and stored *on the chain itself*, so
  every validator runs exactly the same rules, and the rules can be upgraded without restarting
  anything.

Because every validator must compute exactly the same result, the runtime is *deterministic*:
no clocks, no randomness, no network, no files, no GPU.

## 2. Host functions: how the runtime asks the node for help

The runtime cannot do anything the node does not offer it. The node offers a fixed list of
**host functions**: "store this value", "hash these bytes", "check this signature". The runtime
calls them like normal functions, and the node runs them as fast native code.

This is the most important idea in this project. Expensive cryptography (post-quantum
signatures, zero-knowledge proofs) becomes a host function. The runtime stays simple and
deterministic, and the node is free to compute the answer however it likes (one CPU core, all
cores, or a GPU), as long as the answer is always the same.

## 3. FRAME and pallets: the runtime is built from modules

Inside the runtime, features are **pallets**: modules with their own storage, their own
transactions ("calls") and their own events. The Polkadot SDK ships many (balances, sudo,
timestamps…), and Canggu adds its own (`pallet-zk-verifier`, `pallet-pq-intents`,
`pallet-sealed-ordering`, `pallet-parallel-payroll`). The framework that ties pallets together is
called **FRAME**.

## 4. Transactions (extrinsics) and transaction extensions

A transaction is called an **extrinsic**. A signed extrinsic carries a call, the sender, a
signature, and a list of **transaction extensions**: small checks that run before and after the
call. Examples: "the nonce is correct", "the sender can pay the fee", "this was signed for this
chain". Canggu adds two:

- `CheckDagParents`: "this transaction may only run after these other transactions";
- `ChargeTransactionPaymentNoTip`: the normal fee check, but tips are refused.

## 5. The transaction pool already orders by dependencies

Every validated transaction tells the pool which **tags** it *provides* and which it *requires*.
A transaction becomes *ready* only when all the tags it requires are provided by transactions
already on-chain or already ready. Normally the tags are just `(account, nonce)`, so your second
transaction waits for your first. That is already a dependency graph (a DAG), which is why
Canggu's "DAG mempool" turned out to be a small extension rather than a new mempool. See
[Transactions that wait for each other](../features/dag-ordering.md).

## 6. Consensus: Aura and GRANDPA

- **Aura** gives block production to validators in turn. Each one gets a fixed *slot* (2 seconds
  in Canggu) and is the only leader in that slot.
- **GRANDPA** finalises blocks. Validators vote, and once more than two-thirds agree, a block and
  all its ancestors are final and can never be reverted.

Together they give "a rotating leader plus BFT finality", which is what Canggu's v1.3 whitepaper
asked for. See [Sub-second finality](../features/finality.md).

## 7. Weights: paying for execution time

Every call declares a **weight**: an estimate of how long it takes on reference hardware. Blocks
have a weight limit, and fees follow weight. Real chains measure weights with benchmarks. In this
research prototype they are hand-set estimates, which is one of the known
[limitations](../results/limitations.md).

## 8. Standalone chain, not a parachain

Canggu runs as a standalone chain. This matters: on a Polkadot parachain, the relay chain's
validators re-run every block using only Polkadot's standard host functions. Canggu's custom host
functions (post-quantum signatures, proof verification, GPU batches) would not exist there.
