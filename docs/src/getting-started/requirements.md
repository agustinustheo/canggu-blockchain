# Requirements

This chapter gives the hardware and software that you need. The procedures in this part of the
book use ASD-STE100 Simplified Technical English (see [About these docs](../appendix/about-these-docs.md)).

## Hardware

| Item | Minimum | Tested with |
| --- | --- | --- |
| Computer | 64-bit macOS or Linux | Apple M4 Pro, macOS |
| Memory | 16 GB (24 GB for SP1 proofs) | 24 GB |
| Free disk space | 20 GB (30 GB with SP1) | — |
| GPU | Not necessary. Apple silicon is necessary for the Metal backend. | Apple M4 Pro GPU |

> **CAUTION:** All tests and measurements in this book were done on one Apple M4 Pro computer.
> Linux builds are not tested. The Metal GPU backend operates on macOS only.

## Software

| Item | Version | Why you need it |
| --- | --- | --- |
| [rustup](https://rustup.rs) | Current | It installs the Rust version that the repository pins (1.93.0). |
| Rust targets `wasm32-unknown-unknown`, `wasm32v1-none` | — | They compile the runtime. `rust-toolchain.toml` adds them automatically. |
| `protoc` (Protocol Buffers compiler) | Any recent | The Polkadot SDK networking code needs it. |
| A C/C++ compiler (clang) | Any recent | RocksDB and other dependencies need it. On macOS, install the Xcode Command Line Tools. |
| `git` | Any recent | It gets the source code. |

### Optional software

| Item | Version | Why you need it |
| --- | --- | --- |
| [`sp1up`](https://docs.succinct.xyz) (SP1 toolchain) | v6.10.0 | Only if you make SP1 proofs or rebuild the SP1 programs. |
| [`mdbook`](https://github.com/rust-lang/mdBook) | 0.4 | Only if you build this book. |
| [`tectonic`](https://tectonic-typesetting.github.io) | Any recent | Only if you build the whitepaper PDF. |

## Install the software (macOS)

1. Install the Xcode Command Line Tools:
   ```bash
   xcode-select --install
   ```
2. Install `protoc` with Homebrew:
   ```bash
   brew install protobuf
   ```
3. Install rustup. Accept the default settings:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
4. Open a new terminal. Make sure that `cargo` is available:
   ```bash
   cargo --version
   ```

You do not install Rust 1.93.0 manually. The first `cargo` command in the repository installs it.
