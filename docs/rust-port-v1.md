# Rust port status

State slice: `security-alignment-os-foundation-v1`.

Rust is now the canonical implementation and the only implementation exercised
by the repository gate. The crate covers typed proposals, claim validation,
admission, single-use capability consumption, digest-chained journals, accepted
evidence, reversible runtime execution, freeze/kill, specialist consent,
tool manifest drift, fixed compute receipts, shadow/canary governance, local
benchmark families, prediction locks, artifact manifests, explicit Phase 0
contracts, deterministic fault injection, and runtime audit persistence.

The former Python implementation and test harness have been removed from the
active repository. Rust is the only implementation and test surface under this
slice. Git history retains the migration path without leaving a second runtime
or language gate in the checkout.

The Rust gate is:

```text
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The port remains local contract evidence. Rust does not establish OS sandbox
enforcement, authenticated identity, provider execution, model execution,
cryptographic proof, scientific alignment, deployment, or settlement.
