# Use the `canggu` command line

`canggu` is a small wallet and test tool. It signs every transaction with ML-DSA-65. It connects
to a node at `http://127.0.0.1:9944` (change this with `--url`).

> **WARNING:** The keys `//Alice`, `//Bob`, `//Charlie`, `//Dave` and `//Eve` are public test
> keys. They exist only to make testing easy. Do not use them for real value.

## Accounts and transfers

| Command | What it does |
| --- | --- |
| `canggu account //Alice` | Shows the account address and the key sizes. |
| `canggu balance //Eve` | Shows the free balance of an account. |
| `canggu transfer --from //Dave --to //Eve --amount 1.5` | Sends 1.5 CGU. |
| `canggu transfer --from //Dave --to //Eve --amount 1 --after //Bob:0` | Sends 1 CGU, but only after Bob's transaction with nonce 0. |
| `canggu payroll --from //Alice --pay //Bob=10 --pay //Charlie=20` | Pays many accounts with one debit. |

## Batches of signed intents

| Command | What it does |
| --- | --- |
| `canggu intents --count 640 --forge 4` | Signs 640 transfer intents, changes 4 of them after signing, and sends all in one transaction. The chain accepts 636 and refuses 4. |
| `canggu intents --count 8 --senders 4 --compressed` | Proves all 8 signatures with SP1, then sends only the intents and one proof. |

## Sealed ordering

| Command | What it does |
| --- | --- |
| `canggu sealed` | Commits four hashes, reveals three in reverse order, and shows that execution follows the canonical order. |

## Zero-knowledge proofs

| Command | What it does |
| --- | --- |
| `canggu zk-setup --recipients 3` | Makes Groth16 keys for a 3-salary payroll. |
| `canggu zk-register --from //Bob` | Stores the verifying key on-chain. |
| `canggu zk-prove --salt 7 --amounts 100,200,300` | Makes a Groth16 proof. |
| `canggu zk-submit --from //Bob` | Sends the proof to the chain for verification. |
| `canggu zk-sp1 --from //Alice --salt "october payroll" --amounts 3000,4500,1250` | Makes a quantum-safe SP1 proof of the same kind of statement and sends it. |

> **WARNING:** `canggu zk-setup` makes the Groth16 keys on one computer. The random values that it
> uses ("toxic waste") let that computer forge proofs. Use these keys only for tests.

### Prepare the SP1 prover

The commands `canggu zk-sp1` and `canggu intents --compressed` call a separate prover program,
`canggu-sp1`. The wallet does not include it, because the SP1 SDK is very large.

1. Build the prover:
   ```bash
   cd sp1
   export CARGO_TARGET_DIR=/tmp/canggu-sp1-target
   cargo build --release -p canggu-sp1-prover --bin canggu-sp1
   cd ..
   ```
2. Tell the wallet where the prover is:
   ```bash
   export CANGGU_SP1_PROVER=/tmp/canggu-sp1-target/release/canggu-sp1
   ```

> **CAUTION:** One SP1 proof uses approximately 14 to 17 GB of memory and takes one minute or
> more. Close large applications before you make a proof.

## Measurements

| Command | What it does |
| --- | --- |
| `canggu finality --seconds 40` | Measures the time from a new block to its finalisation. |
| `canggu bench` | Measures ML-DSA-65 and Groth16 speed on this computer. It does not need a node. |
