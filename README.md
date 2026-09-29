# Security Alignment OS

State slice: `security-alignment-os-foundation-v1`.

A runnable Rust-native local reference implementation of the HSAI
proposal-to-rollback control loop. It integrates evidence review records,
admission, single-use capabilities, consented specialist memory, a separate
capability broker process, one sandboxed file transformation, rollback, fixed
receipts, governance, and audit persistence. It does not run a model or
establish scientific alignment, authenticated independent review, or
production readiness.

```text
consented tenant note + immutable specialist identity
  -> typed action proposal
  -> exact-subject evidence review record
  -> deterministic admission
  -> kernel-bound single-use capability
  -> external broker + isolated file transformation
  -> evidence/lease/telemetry observation
  -> completion or rollback + freeze/shutdown
```

## Run

Rust 1.77+.

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --bin local_demo
cargo run --bin capability_broker -- <socket> <workspace> <journal> <evidence.json> <capability_supervisor>
cargo run --bin broker_adversarial_runner -- <socket> <request.json> <workspace> <capability_supervisor>
pnpm run lint
```

The Rust test suite exercises completion, rollback, specialist consent, local
audit persistence, and one fixed integer-sum receipt. It makes no provider
calls or settlement transactions. The Confidential Space and Nitro runner
binaries use platform attestation interfaces only when launched in those
environments. Hermetic local tests execute the workload functions against
actual local runner, broker, and evaluator binaries, using synthetic protocol
and attestation adapters; they do not call platform attestation. Nitro image
identity checks derive the clean Git revision and source-tree digest, verify
the digest at build time, embed it in the runner, and reject runtime overrides.
They do not build an image.

tests/security_thesis_e2e.rs exercises the public evidence-to-capability,
receipt, mutation, audit, rollback, claim-composition, and fail-closed
boundaries. tests/local_demo_e2e.rs asserts the executable demo's disposition,
state digest, state slice, and claim ceiling. The attestation binaries have
hermetic protocol/envelope tests with synthetic fixtures; those do not emulate
Google or AWS attestation.

The heavy gate is `pnpm run lint`. Faster gates are `lint:fast`, `test:focused`,
`verify:contracts` and `verify:full`. `verify:contracts` also checks the frozen
build-contract digest before running Clippy. No JavaScript runtime dependencies
are installed.

## Components

| Module | Implemented behavior |
| --- | --- |
| `adaptation` | Proposal-only candidate and local work-offer selection; shadow staging only, with no execution or settlement authority |
| `adapters` | Validates typed external sandbox and invocation requests; does not execute them |
| `alignment` | Digest-bound prediction/configuration lock; no model execution or assessment effect |
| `Kernel`, `ReplayJournal` | Validated policy, exact issuer/candidate/policy binding, claim expiry, budgets, single-use execution, lifecycle enforcement, and locked, synced caller-owned snapshot persistence |
| `checker` | Independent local recomputation of replay, lifecycle, audit, fixed-job, and signed-capability receipt invariants |
| `EvidenceRegistry` | Subject-bound evidence, distinct local review roles, freshness, revocation, and canonical persistence/recovery |
| `benchmark` | Deterministic local adversarial contract cases across fit, tune, and assessment labels; no model execution |
| `artifacts` | Quarantined artifact manifests with subject/source/provenance digests, retention, review, revocation, and canonical persistence/recovery |
| `custody` | Owner-declared custody records plus descriptor-relative local artifact, effective-UID, permission, size, and digest checks; owner mapping and deletion remain caller-owned |
| `claims` | Meet-only claim envelopes and digest-only aggregate release packets |
| `contract` | Explicit capability lattice, lifecycle transitions, and validated/recoverable caller-owned failure budgets wired to kernel freeze decisions |
| `property` | Exhaustive local lattice/lifecycle checks and digest-only invariant reports |
| `receipts` | Ed25519-signed capability receipts with exact decision binding and local replay rejection |
| `execution_gate` | Typed sandbox/request boundary that validates controls and remains blocked locally |
| `broker`, `capability_broker`, `capability_supervisor` | Separate Unix IPC broker, broker-only receipt issuer, staged uppercase file transformation, canonical journal, timeout/kill path, network-denied host sandbox, and frozen crash recovery |
| `broker_adversarial_runner` | Separate hostile client for direct supervisor, path escape, replay, forged receipt, malformed child operation, and telemetry containment attempts |
| `maintenance_replication` | Canonical, signed two-report v2 packet binding the maintenance broker executable digest; legacy v1 packets remain verifiable without that binding |
| `maintenance_replication_runner` | Operator-controlled freeze, isolated 20-scenario real-process execution, per-launch broker digest checks, private evidence capture, signed host-report production, and packet assembly |
| `maintenance_replication_verifier` | Digest-only validator for an exchanged replication packet; it performs no maintenance or network execution |
| `maintenance_confidential_space_runner`, `maintenance_nitro_enclave_runner` | Environment-specific machine-attestation wrappers; local workload tests use synthetic adapters. Nitro source identity is derived from a clean Git tree, checked against copied build inputs, embedded at compile time, and bound into attestation user data. No platform attestation or image build is performed. The GCP wrapper's token output is blocked pending protected custody |
| `schema` | Versioned schema identities with exact digest-bound lookup and canonical recovery |
| `Runtime`, `AuditJournal` | Reversible dictionary actions, terminal freeze/kill, and digest-chained audit snapshots with locked, synced replacement and validated pending recovery |
| `specialist`, `memory` | Immutable specialist identities, a shared canonical consent/revocation registry, consented retrieval, redacted telemetry, frozen tool manifests, and durable memory with caller-owned consent recovery |
| `routing` | Digest-only caller-selected specialist routing bound to active tenant consent and immutable identity |
| `integration` | Evidence-bound workflow execution, receipt-gated execution, lifecycle completion/quarantine, observation, rollback, freeze, and kill disposition |
| `maintenance` | In-memory fixed-packet workflow contract; hermetic executor only |
| `market` | Fixed local sum with job/input commitments, typed exact-offer receipts, result recomputation, binding/timeout/replay checks, and an authorization-required settlement proposal |
| `governance` | Shadow/canary/local-release records with immutable base, phase evidence, lifecycle validation, and canonical persistence/recovery |
| `faults` | Deterministic replay, stale-clock, stale-policy, malformed-bytes, partial-write, and kill/freeze scenarios |

## Boundaries

Callers own policy, clock, identity assertions, storage paths and observations.
The capability broker is a separate process and the supervisor has a host
sandbox boundary for the one supported operation. A hostile same-UID process
with workspace access can still interfere with caller-owned files or race
filesystem state; this slice does not claim authenticated host identity or
complete multi-tenant isolation. Persisted content is plaintext in
caller-owned storage; digests detect accidental or uncoordinated tampering,
not an attacker able to rewrite both content and digest. Opened persistent
consent registries coordinate local grant updates and gated memory effects with
an owner-only single-writer lock. A saved and recovered consent revocation
blocks access to the revoked grant ID. Consent snapshots remain unauthenticated
and can be rolled back to older valid bytes; revocation does not claim secure
disk erasure. Persistent memory serializes each cooperating local read, write,
and delete with a per-file lock, then reloads the current snapshot while the
lock is held so stale handles do not erase concurrent records. `save` persists
the latest snapshot and refreshes the handle under that lock. The lock fails
closed if left behind by a crashed writer; `len` and `is_empty` report the handle's last
loaded view. This does not protect against a hostile same-UID process.
Memory snapshots are plaintext, owner-only on Unix, and reject symlink or
broader-permission files; this does not protect against a hostile same-UID
process or provide encryption.

The remaining production gates include authenticated reviewers, Linux host
hardening and independent replication, secret custody beyond the transient
launch token, model serving/training, held-out scientific evaluation, external
red-team replication, deployment and settlement. The local tests do not
satisfy those gates.

The Confidential Space runner currently places its OIDC attestation token in
the stdout envelope. The image sets `tee.launch_policy.log_redirect` to
`never`, but no protected output sink is wired in this repository. Do not
launch it; secure output custody remains an external gate. The token and
deployment path are outside the local tests and claim ceiling.

## Build records

- [Repository maintenance integration and ordered exit gates](docs/maintenance-integration-v1.md)
- [Fixed maintenance broker and evaluator process](docs/maintenance-process-v1.md)
- [Replication report v2 and broker executable binding](docs/maintenance-replication-v2.md)
- [Separate-host maintenance replication contract](docs/maintenance-replication-v1.md)
- [Maintenance replication runner](docs/maintenance-replication-runner-v1.md)
- [Confidential Space runner output gate](docs/maintenance-confidential-space-v1.md)
- [Nitro enclave runner](docs/maintenance-nitro-enclave-v1.md)
- [GCP TDX machine-attested record](docs/maintenance-gcp-tdx-record-v1.md)
- [Proposal-only adaptation exploration](docs/adaptation-exploration-v1.md)
- [Frozen contract](docs/build-contract-v1.md)
- [Integration and remaining gates](docs/integration-v1.md)
- [Local end-to-end assurance protocol and claim ceiling](docs/local-assurance-v1.md)
- [Kernel](docs/kernel-v1.md)
- [Evidence and evaluation](docs/evidence-evaluation-v1.md)
- [Artifact manifests](docs/artifacts-v1.md)
- [Custody records](docs/custody-v1.md)
- [Claim envelopes](docs/claims-v1.md)
- [Phase 0 contract](docs/phase0-contract-v1.md)
- [Deterministic property checks](docs/property-checks-v1.md)
- [Signed capability receipts](docs/receipts-v1.md)
- [External execution gate](docs/execution-gate-v1.md)
- [External capability broker](docs/broker-v1.md)
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
