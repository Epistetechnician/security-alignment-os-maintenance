# Evidence and evaluation V1

State slice: `security-alignment-os-foundation-v1`.

This lane is a Rust pure-data contract. It does not call a model or provider,
authenticate a reviewer, inspect external custody, establish artifact truth, or
make a behavioral, mechanistic, alignment, benchmark, or production claim.
Local fixtures and green tests are regression evidence only.

## Evidence acceptance

`Evidence` binds an ID to a lowercase SHA-256 subject digest, local operator and
validator role assertions, an independent reviewer, and an exclusive validity
interval. `EvidenceRegistry::insert` rejects duplicate IDs, malformed digests,
empty roles, operator/validator collisions, and inconsistent pre-accepted
records. `accept` rejects revoked records, repeated acceptance, empty reviewers,
and reviewer role collisions. `revoke` permanently invalidates a record.

```rust
let mut registry = EvidenceRegistry::default();
registry.insert(Evidence { /* exact subject and distinct local roles */ })?;
registry.accept("evidence-id", "reviewer")?;
assert!(registry.is_valid("evidence-id", now, &subject_digest));
```

`is_valid` checks acceptance, revocation, freshness, exact subject binding, and
three distinct non-empty local role assertions. These identities are caller
inputs; no external reviewer or signature is authenticated.

`EvidenceRegistry::validate` checks persisted key/ID and lifecycle bindings.
`save`, `load`, and `recover` use canonical JSON and temporary-file promotion;
they validate local persistence but do not authenticate custody or reviewers.

## Prediction lock

`alignment::PredictionLock` hashes protocol, prediction and configuration
identifiers at construction. `lock_fit` and `accept_independently` are explicit
one-way flags. `validate` permits an assessment seam only when both flags are
set. The lock is a contract; it does not execute a model, unlock a dataset,
authenticate a review, or promote an alignment claim.

## Clean local adversarial families

`benchmark::families` returns eight fixed denial families plus one nominal
control case for each of the `fit`, `tune`, and `assessment` labels. The cases
exercise authority requests, network/tool misuse, malformed provenance,
resource over-budget, unsupported self-modification, and spend actions.
`benchmark::run_aggregate` drives each case through admission, runtime
consumption, lifecycle completion, and independent replay/lifecycle checks,
then returns only the split label and pass counters; `run_all` evaluates all
three labels.

These families test control-plane behavior only. They are not held-out model
evidence, causal alignment evidence, general safety evidence, or production
readiness evidence.

`checker::validate_replay`, `validate_audit`, `validate_receipt`, and
`validate_capability_receipt` recompute public record equations independently
of producer validators. The capability-receipt check also verifies the
Ed25519 signature over the canonical receipt payload. These are local
consistency checks; they do not authenticate a reviewer, prove custody, or
verify an external execution environment.

## Focused validation

```text
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The repository gate dispatches those commands through `pnpm`; no second-language
runtime or package manager is required.
