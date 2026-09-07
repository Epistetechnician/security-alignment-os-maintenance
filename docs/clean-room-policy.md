# Implementation reuse and provenance

State slice: `security-alignment-os-foundation-v1`.

The user request of 2026-09-07 permits leveraging existing local and eligible
open-source implementations. This replaces the earlier blanket prohibition
on implementation reuse. Preserve source revision, exact working-byte digest,
license, notices and modifications for any copied implementation. Unknown
rights means reference-only; no redistribution inference from local access.

This build extends the Rust foundation directly. The Rust HSAI
control-plane and composed-platform hosted-runtime interfaces inform the design;
no Rust code is copied or translated. The exact consulted inputs are recorded
in `source-intake-v1.json`. Public specifications inform tool manifest and
provenance contracts. The crate has no external runtime service; its serde,
hashing and error crates are pinned by `Cargo.lock`.

Scientific corpora, traces, model outputs, checkpoints, closed experiments,
credentials and private evidence are excluded. No source inspection changes
those experiments or imports their claim status.

Future SDK/runtime adoption requires an exact dependency lock, license notices,
build recipe, runtime assumptions and conformance tests. A current documentation
page is design context, not a pinned dependency or reproduced SOTA result.
