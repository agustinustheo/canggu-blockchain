# Parallel payroll

**Code:** [`pallets/parallel-payroll/`](https://github.com/agustinustheo/canggu-blockchain/tree/main/pallets/parallel-payroll)

## In plain words

The Canggu whitepaper's main example is a payroll: an employer pays many employees at once. The
whitepaper splits it into a CPU part (check the employer's balance and take the total once) and a
GPU part (credit all employees in parallel).

`pallet-parallel-payroll` has one call, `batch_pay`, that does exactly that split:

1. **Sequential part:** add up the payments (with overflow checks), check the employer can pay,
   and take the total from the employer **once**.
2. **Parallel part:** credit each recipient.

```text
=== 4. Payroll: one debit, conflict-free parallel credits ===
  5F3ohmaD…: +1000.0000 CGU
  5EKGfkiy…: +2000.0000 CGU
  5F3bxbZ4…: +1500.0000 CGU
  5FqiwtSw…: +2500.0000 CGU
  batch paying Bob twice: rejected with Payroll::DuplicateRecipient
```

## What makes the credits "parallel"

The pallet refuses a batch in which a recipient appears twice, or in which the employer is also a
recipient. Then every credit writes to a different account, so the credits can run in any order,
or at the same time, and the result is the same. That property (*disjoint writes*) is what a
parallel executor needs.

## Why the credits still run one after another today

A Polkadot SDK runtime is single-threaded WebAssembly, and each credit is mostly a read and a write
of the state database. A GPU cannot speed that up. The whitepaper's claim that 10,000 transfers
take "under 1 ms" on a GPU confuses adding numbers with updating 10,000 database entries.

So the pallet guarantees the *contract* (no conflicts), not the speed-up. The speed-up would come
from executing conflict-free work on several CPU cores, which is where Polkadot's newer designs
(such as JAM) are going.

## Limits

- Weights are linear estimates, not benchmarks.
- "Parallel gas" pricing (from the whitepaper) only makes sense once execution is really parallel.
  Until then, the chain charges single-core cost.
