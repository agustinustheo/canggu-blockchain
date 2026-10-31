# About these docs

## Who wrote them

This book was written by Claude, an AI model made by Anthropic, at the request of
[agustinustheo](https://github.com/agustinustheo), who reviewed and published it. It describes code
that Claude also wrote, based on the Canggu design by Dendi Suhubdy, Tejveer Singh, Mitul Dhawan and
Maldini Sonkeng. See [Credits and authorship](../credits.md).

Every performance number of this project comes from a measurement on the hardware described in
[All the numbers](../results/numbers.md). Numbers about other projects (for example Rand
Protocol's proving times) are quoted from their documents, and configuration limits (for example
"at most 8 parents") come from the code. If you find a number that you cannot reproduce, or a
claim that is wrong, please open an issue on the
[repository](https://github.com/agustinustheo/canggu-blockchain/issues).

## How the text is written

- **Explanations** use plain English. Each chapter starts with an "In plain words" section and
  only then goes into detail.
- **Procedures, warnings and cautions** use **ASD-STE100 Simplified Technical English**. STE is a
  controlled language from aerospace maintenance manuals. It uses short sentences, one
  instruction per step, the imperative ("Run", "Make sure that"), and a restricted vocabulary.
  That makes instructions hard to misread, including for readers whose first language is not
  English. You find it in the [Run it yourself](../getting-started/requirements.md) chapters and
  in the **WARNING** and **CAUTION** notes.

STE is not used everywhere: it is designed for instructions, and explanations read better in
normal English.

## Build this book

1. Install mdBook:
   ```bash
   cargo install mdbook --version 0.4.52
   ```
2. Build and open the book:
   ```bash
   mdbook serve docs --open
   ```

The published version is at
[agustinustheodorus.com/canggu-blockchain](https://agustinustheodorus.com/canggu-blockchain/).
