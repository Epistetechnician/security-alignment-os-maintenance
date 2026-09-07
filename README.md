# Security Alignment OS

State slice: `security-alignment-os-foundation-v1`.

A runnable Rust-native local reference implementation of the HSAI
proposal-to-rollback control loop. It integrates evidence review records,
admission, single-use capabilities, consented specialist memory, local
execution, monitoring, rollback, fixed receipts, governance, and audit
persistence. It does not run a model or establish scientific alignment, OS
isolation, authenticated independent review or production readiness.

```text
consented tenant note + immutable specialist identity
  -> typed action proposal
  -> exact-subject evidence review record
  -> deterministic admission
  -> kernel-bound single-use capability
  -> reversible dictionary execution
  -> evidence/lease/telemetry observation
  -> completion or rollback + freeze/shutdown
```

## Run

Rust 1.77+.

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --bin local_demo
pnpm run lint
```

The Rust test suite exercises completion, rollback, specialist consent, local
audit persistence, and one fixed integer-sum receipt. It makes no provider
calls or settlement transactions.

The heavy gate is `pnpm run lint`. Faster gates are `lint:fast`, `test:focused`,
`verify:contracts` and `verify:full`. `pnpm` only dispatches Cargo checks; no
JavaScript runtime dependencies are installed.

## Components

| Module | Implemented behavior |
| --- | --- |
| `Kernel`, `ReplayJournal` | Validated policy, exact issuer/candidate/policy binding, claim expiry, budgets, single-use execution, lifecycle enforcement, kernel snapshots, and atomic journal persistence |
| `checker` | Independent local recomputation of replay, lifecycle, audit, fixed-job, and signed-capability receipt invariants |
| `EvidenceRegistry` | Subject-bound evidence, distinct local review roles, freshness, revocation, and canonical persistence/recovery |
| `artifacts` | Quarantined artifact manifests with subject/source/provenance digests, retention, review, revocation, and canonical persistence/recovery |
| `custody` | Owner-declared external custody and bounded retention records with canonical recovery |
| `claims` | Meet-only claim envelopes and digest-only aggregate release packets |
| `contract` | Explicit capability lattice, lifecycle transitions, and validated/recoverable caller-owned failure budgets wired to kernel freeze decisions |
| `property` | Exhaustive local lattice/lifecycle checks and digest-only invariant reports |
| `receipts` | Ed25519-signed capability receipts with exact decision binding and local replay rejection |
| `execution_gate` | Typed sandbox/request boundary that validates controls and remains blocked locally |
| `schema` | Versioned schema identities with exact digest-bound lookup and canonical recovery |
| `Runtime`, `AuditJournal` | Reversible dictionary actions, terminal freeze/kill, and digest-chained audit persistence |
| `specialist`, `memory` | Immutable specialist identities, consented retrieval, revocation, redacted telemetry, frozen tool manifests, and canonical durable memory/registry snapshots with crash recovery |
| `routing` | Digest-only caller-selected specialist routing bound to active tenant consent and immutable identity |
| `integration` | Evidence-bound workflow execution, receipt-gated execution, lifecycle completion/quarantine, observation, rollback, freeze, and kill disposition |
| `market` | Fixed local sum with job/input commitments, typed offers, result recomputation, binding/timeout/replay checks, and an authorization-required settlement proposal |
| `governance` | Shadow/canary/local-release records with immutable base, phase evidence, lifecycle validation, and canonical persistence/recovery |
| `faults` | Deterministic replay, stale-clock, stale-policy, malformed-bytes, partial-write, and kill/freeze scenarios |

## Boundaries

Callers own policy, clock, identity assertions, storage paths and observations.
Same-process Rust objects are not a sandbox against malicious code.
Kernel issuance is process-local; journal persistence is audit persistence,
not distributed authority or cross-process replay protection. Persisted content
is plaintext in caller-owned storage; digests detect accidental or
uncoordinated tampering, not an attacker able to rewrite both content and
digest. Consent revocation blocks access; it does not claim secure disk erasure.

The remaining production gates include authenticated reviewers, real sandbox
and egress enforcement, secret custody, model serving/training, held-out
scientific evaluation, external red-team replication, deployment and settlement.
The local tests do not satisfy those gates.

## Build records

- [Frozen contract](docs/build-contract-v1.md)
- [Integration and remaining gates](docs/integration-v1.md)
- [Kernel](docs/kernel-v1.md)
- [Evidence and evaluation](docs/evidence-evaluation-v1.md)
- [Artifact manifests](docs/artifacts-v1.md)
- [Custody records](docs/custody-v1.md)
- [Claim envelopes](docs/claims-v1.md)
- [Phase 0 contract](docs/phase0-contract-v1.md)
- [Deterministic property checks](docs/property-checks-v1.md)
- [Signed capability receipts](docs/receipts-v1.md)
- [External execution gate](docs/execution-gate-v1.md)
- [Schema registry](docs/schema-v1.md)
- [Fault injection](docs/fault-injection-v1.md)
- [Plan conformance](docs/plan-conformance-v1.md)
- [Runtime and specialist](docs/runtime-v1.md)
- [Rust port status](docs/rust-port-v1.md)
- [Source intake](docs/source-intake-v1.json)
- [Reuse policy](docs/clean-room-policy.md)

The Rust implementation extends this repository directly and uses the HSAI
840–842 plan plus eligible local/public references recorded in the intake
manifest. No closed research artifacts, scientific corpora, traces or model
outputs were imported.
