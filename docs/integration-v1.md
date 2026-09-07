# Local end-to-end integration

State slice: `security-alignment-os-foundation-v1`.

The build uses the 840 architecture, 841 parallel plan and 842 reference map in
composed-zk-benchmark-os as design inputs. It extends this repository's Rust
implementation. Consulted source revisions and exact working bytes are
recorded in `source-intake-v1.json`. No external code or scientific data was
copied. The implementation has no third-party runtime services.

## Implemented local path

`integration::run` binds the exact proposal digest to accepted evidence before
admission. The kernel records a digest-chained decision and issues a single-use
capability. `Runtime::execute` validates the full capability and action payload,
consumes authority immediately before the state commit, records a checkpoint,
and retains metadata-only audit entries. `integration::run` returns a digest-only
`WorkflowResult`; unhealthy and missing-telemetry observations roll back the
latest checkpoint and freeze the runtime, while an explicit kill request rolls
back and marks the runtime killed.

`run_local_workflow` remains a compact compatibility seam for callers that need
only `quarantined`, `rejected`, or `completed` dispositions.

`integration::run_with_receipt` adds a typed `ReceiptBinding` seam. It admits
the proposal, verifies the signed receipt against the resulting decision and
current policy, and only then calls the same execution/observation path. A
receipt failure returns `Quarantined` with no runtime state or audit mutation.

`cargo run --bin local_demo` exercises this path with a fixed local proposal
and prints only the workflow disposition and digests.

## Durable local surfaces

`memory::PersistentMemory` stores canonical JSON records under a caller-selected
path. Each write, read, and delete requires an active consent grant, a matching
registered specialist, and a resource scope. The file stores value digests and
grant IDs; grants must be reconstructed after restart. The file is plaintext and
caller-owned, and deletion is logical deletion rather than secure erasure.

`audit::AuditJournal` provides the corresponding caller-owned audit snapshot. It
hashes event metadata and state digests into a canonical chain, validates the
chain and canonical bytes on load, supports temporary-snapshot recovery when
the primary is absent, and uses atomic replacement for a selected destination.
It does not provide authenticated authorship or cross-process append locking.

`artifacts::ArtifactRegistry` has the same canonical persistence boundary for
manifest lifecycle records. `validate` rejects inconsistent status,
timestamp, role, and manifest bindings before `save` or after `load`;
`recover` promotes only a valid temporary snapshot when the primary is absent.
This is persistence validation, not proof of external custody or deletion.

`custody::CustodyRegistry` records an owner-declared external `0700` root,
bounded raw-retention interval, exact artifact digest, validator assertion, and
terminal owner deletion record. `claims::ClaimEnvelope` composes evidence by
meet only, while `AggregateReleasePacket` retains claim IDs and evidence
digests without raw payloads. Both remain caller-owned local records.

`checker` independently recomputes replay, audit and fixed-receipt invariants
for local regression. Its result is not independent acceptance evidence.

`alignment::PredictionLock` binds the protocol, prediction, configuration and
lock-state digests. Fit completion and independent acceptance remain caller
assertions; canonical save/load/recovery detects snapshot tampering but does
not authenticate a reviewer or open assessment effects.

`EvidenceRegistry` snapshots can be saved, loaded, and recovered through a
canonical temporary-file boundary. Accepted/revoked records are revalidated
on every load, including subject, role, and lifecycle fields.

`receipts::ReceiptSigner` can issue an Ed25519 signature over a capability
receipt only after proposal, decision, policy, capability, subject, and
validity bindings recompute exactly. `receipts::ReceiptVerifier` checks the
signature, freshness, bindings, trusted local key registry, and process-local
replay set. This authenticates bytes under a caller-provided key; it does not
authenticate the host or make the signer independent.

## Downstream local contracts

`market::SumJob` accepts one fixed non-negative integer-sum job class. A separate
verifier recomputes the result, checks program/input/time/price/status bindings,
rejects a repeated receipt digest, and permits one unexecuted settlement
proposal. No provider, wallet, chain,
zero-knowledge, FHE, or MPC workload runs.

`governance::ReleaseRegistry` preserves an immutable base and rollback target.
Shadow and canary advances require the candidate's first evidence digest, then a
distinct lowercase digest for the next phase. `freeze` is terminal metadata; it
does not deploy an adapter or authorize an external executor. Registry
snapshots validate candidate identity, phase evidence cardinality, and
canonical bytes before save/load/recovery.

`specialist::SpecialistRegistry` and `specialist::ToolRegistry` bind immutable
identity snapshots with canonical persistence/recovery. The tool registry
binds tool ID/version, implementation digest and a
canonical manifest-list digest, supports exact invocable lookup, terminal
revocation, and canonical persistence. `adapters::AdapterPlan` validates the
shape of an external sandbox/invocation request but rejects external execution
authorization in this foundation slice. `execution_gate::ExecutionGate`
validates a typed sandbox attestation and external job request, then returns a
blocked disposition for every valid request.

## Remaining execution gates

- OS sandbox, egress deny policy, secret broker and process kill enforcement;
  the execution gate is a record validator, not enforcement.
- Authenticated role/validator identities and independently reviewed evidence.
- Model serving, consented training-data custody, candidate training and real
  held-out behavioral or causal evaluation.
- Production canary deployment, external red-team replication and recovery
  drills.
- Provider receipt authentication, cryptographic proof verification and
  separately authorized settlement.

These are unimplemented external gates, not passing results inferred from local
fixtures. The local claim ceiling remains pure-data control and caller-owned
persistence evidence.
`integration::run_with_artifact` accepts an `EvidenceBinding` containing both
references. It adds an accepted `ArtifactManifest` check that binds the
proposal's source digest to the artifact subject before the same workflow
proceeds.
