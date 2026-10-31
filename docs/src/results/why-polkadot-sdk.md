# Why the Polkadot SDK made this possible

Canggu's whitepaper reads like a chain built from scratch: its own consensus, its own mempool, its
own signature scheme, its own execution model. That is normally years of work. On the Polkadot SDK,
almost every one of those turned out to be a **hook the framework already had**. This is the main
lesson of the project.

## Every big idea mapped onto an existing extension point

| Canggu idea | What you might expect to build | What the Polkadot SDK already had | How much new code |
| --- | --- | --- | --- |
| Post-quantum signatures | A new transaction format and a new node | The runtime's signature type is a type parameter (`Verify`) | One enum and one host function |
| DAG mempool | A new mempool | The transaction pool already orders by `provides`/`requires` tags | One transaction extension |
| No fee auction | Changes to block building | Fees are a transaction extension | A wrapper around the standard one |
| Expensive cryptography | A faster VM | Host functions: native code the runtime can call | One function per algorithm |
| GPU acceleration | A GPU-aware runtime | The same host functions: the node picks how to compute them | A backend behind one trait |
| zkVM proofs | Protocol changes | A pallet plus a host function | Two calls and one host function |
| Rotating leader + BFT finality | A consensus implementation | Aura + GRANDPA in the template | Two node options for faster finality |
| Sealed ordering | Mempool and block-builder changes | A pallet hook that runs at the start of every block | One pallet |
| Upgrades without forks | Coordination | The runtime is Wasm stored on-chain | Nothing |

The work went into the parts that are actually new: the Metal GPU kernels and the tests that prove
they match the CPU, the SP1 programs and their measurements, and getting the details right.

## The pattern to copy

If you want to build something "very complicated" on the Polkadot SDK, the pattern from this
project is:

1. **Keep the rules in the runtime.** Pallets and transaction extensions decide *what* must be
   true.
2. **Put heavy mathematics in host functions.** The node decides *how* to compute it: native code,
   all cores, or a GPU, as long as the answer is always identical.
3. **Use the existing machinery before inventing new machinery.** The transaction pool's tags,
   the fee extension and the block-initialisation hook replaced what looked like three new
   subsystems.
4. **Measure everything.** Several of the most important results here are negative (signature
   compression does not pay off on a laptop; 50,000 TPS does not fit), and they came from
   measuring, not from reasoning.

## Where the framework pushed back

The Polkadot SDK is not magic, and the places where it resisted are instructive:

- **Consensus keys.** Making block production and finality post-quantum means changing the node's
  keystore and GRANDPA's vote format. That is deep node work, not a pallet.
- **Custom host functions tie you to a standalone chain.** A Polkadot parachain is re-executed by
  relay-chain validators that only have the standard host functions.
- **Large proofs.** Blocks have a size limit, and 1.27 MB SP1 proofs use a lot of it.
- **Dependencies move fast.** Tooling around exact dependency versions took real effort.
