# Sub-second finality

**Code:** [`node/src/service.rs`](https://github.com/agustinustheo/canggu-blockchain/blob/main/node/src/service.rs),
[`scripts/finality.sh`](https://github.com/agustinustheo/canggu-blockchain/blob/main/scripts/finality.sh)

## In plain words

A block is *final* when it can never be undone. The Canggu whitepaper asks for finality in under a
second. With the Polkadot SDK's default settings, a block becomes final about **5 seconds** after
it appears, which makes it look impossible.

It is not impossible. Two cautious default settings cause almost all of the delay. With both
changed, two validators on one computer finalised blocks in a median of **242 ms** with the normal
2-second blocks, and **121 ms** when the block time was also shortened to 500 ms.

## Where the 5 seconds come from

GRANDPA, the finality protocol, works in voting rounds. Two settings slow it down:

1. **Vote lag.** By default validators vote for the block *two behind* the newest one, in case
   the newest one is about to be replaced by a competing block. With 2-second blocks, that alone
   adds 4 seconds. Lowering it does not make finality unsafe: a block is final only when more than
   two-thirds of validators agree, and votes for a block that loses simply finalise the last block
   both sides share.
2. **Gossip duration** (default 333 ms). A validator waits up to 2× this before its first vote and
   4× before its second.

Both are now node options: `--grandpa-vote-lag` and `--grandpa-gossip-ms`. The block time is a
build option: `CANGGU_SLOT_MS`.

## What we measured

`scripts/finality.sh` starts two validators and measures, for each block, the time from its first
appearance to its finalisation.

| Block time | Gossip | Vote lag | Finality, median | 90th percentile |
| ---: | ---: | ---: | ---: | ---: |
| 2 s | 333 ms | 2 (default) | 5 s | 6 s |
| 2 s | 333 ms | 0 | 1 s | 2 s |
| 2 s | 100 ms | 0 | 430 ms | 584 ms |
| 2 s | 50 ms | 0 | **242 ms** | 288 ms |
| 500 ms | 333 ms | 2 | 2 s | 3 s |
| 500 ms | 50 ms | 0 | **217 ms** | 293 ms |
| 500 ms | 25 ms | 0 | **121 ms** | 173 ms |

## Reproduce it

1. Run the measurement with 2-second blocks:
   ```bash
   GOSSIP_MS=50 VOTE_LAG=0 scripts/finality.sh 40
   ```
2. Build with 500 ms blocks, then measure again:
   ```bash
   CANGGU_SLOT_MS=500 cargo build --release -p canggu-node
   CANGGU_SLOT_MS=500 GOSSIP_MS=50 VOTE_LAG=0 scripts/finality.sh 30
   ```

> **CAUTION:** A chain cannot change its block time after it starts. Use `CANGGU_SLOT_MS` only for
> new test chains.

## How to read these numbers

> **CAUTION:** These numbers come from two validators on one computer. Messages between them take
> almost no time. A real network adds delay to every voting round.

- The gossip duration must be longer than the message delay between validators.
- Each round needs about two message delays.
- A validator set with 50–100 ms between members should still finalise in well under a second.
  A set spread around the world, with 200 ms or more between members, probably will not.

Nothing here was tested over a real network. The node's defaults stay at the Polkadot SDK's
cautious values.

## Why not use Polkadot's relay chain?

Running Canggu as a Polkadot *parachain* would give it shared security, but finality would come
from the relay chain and be slower. It would also remove Canggu's custom host functions (relay
validators only have the standard ones), so post-quantum signature checks, proof checks and the GPU
backend would not work as built here.
