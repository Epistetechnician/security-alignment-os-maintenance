# Security Alignment OS — Agent Rules

State slice: `security-alignment-os-foundation-v1`.

Measure twice, cut once policy.

This repository is a Rust-native local reference implementation of claim-bounded
agent security controls. Model output is proposal-only. No provider calls, model
downloads, credentials, network execution, real value movement, production
authority, or scientific alignment claim is permitted in the foundation slice.

Every mutation in this repository must name the state slice
`security-alignment-os-foundation-v1` in its change record or commit message.

Reuse policy (user authorization 2026-09-07): eligible local and open-source
implementation may be reused with exact source revision, working-byte digest,
license and modification records. Do not copy scientific artifacts, datasets,
traces, credentials or private data. Material without established reuse rights
remains reference-only. See docs/source-intake-v1.json. The earlier blanket
clean-room restriction is superseded for implementation code by this request.

Rust is the only implementation language for this repository. Do not add a
second-language implementation under the foundation slice.

Preserve unrelated work. Keep the codebase clean: no temporary files, dead
code, dead files, or generated artifacts. Run the Rust format, test, and Clippy
gates before delivery.
