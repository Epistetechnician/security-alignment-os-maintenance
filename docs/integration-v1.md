# Local end-to-end integration

State slice: `security-alignment-os-foundation-v1`.

The local core uses the 840 architecture, 841 parallel plan and 842 reference
map in composed-zk-benchmark-os as design inputs. It extends this repository's
Rust implementation. Consulted source revisions and exact working bytes are
recorded in `source-intake-v1.json`. No external code or scientific data was
copied. The local core needs no third-party runtime service. Separate hosted
Confidential Space and Nitro runner binaries use their platform attestation
interfaces when launched in those environments. Hermetic local tests execute
the workload functions with the actual local runner, broker, and evaluator
binaries, using synthetic protocol and attestation adapters. They do not call
platform attestation. Nitro image-policy tests bind the clean Git revision to a
digest of the exact image source inputs, check that the Docker build verifies
and embeds both, and reject runtime identity overrides. They do not build an
image.

## Implemented local path

`integration::run` binds the exact proposal digest to accepted evidence before
admission. The kernel records a digest-chained decision and issues a single-use
capability. `Runtime::execute` validates the full capability and action payload,
consumes authority immediately before the state commit, records a checkpoint,
and retains metadata-only audit entries bound to the candidate, decision, policy,
and capability-token digests. The kernel lifecycle follows the same
path: admission records `Admitted`, consumption records `Executing`, healthy
completion records `Completed`, and unhealthy observations record rollback
followed by freeze or kill. `integration::run` returns a digest-only
`WorkflowResult`; unhealthy and missing-telemetry observations roll back the
latest checkpoint and freeze the runtime, while an explicit kill request rolls
back and marks the runtime killed.

When a kernel failure budget is configured, missing evidence, rejected
admission, receipt quarantine, and rollback observations are counted. A
`FreezeRequired` result freezes the kernel's live lifecycles and the
coordinator freezes the runtime before returning its disposition.

If an admitted proposal fails runtime validation before capability consumption,
the coordinator transitions its lifecycle to `Quarantined`, records a
quarantine failure when a budget is configured, and returns the original
rejection without changing runtime state or audit entries. If the kernel had
already quarantined or shut down the lifecycle, that terminal decision is
preserved.

`run_local_workflow` remains a compact compatibility seam for callers that need
string dispositions. It delegates to the same coordinator, so evidence,
failure-budget, lifecycle, rollback, and freeze behavior cannot diverge; it
returns `quarantined`, `rejected`, `completed`, or `rolled_back`.

`integration::run_with_receipt` adds a typed `ReceiptBinding` seam. It admits
the proposal, verifies the signed receipt against the resulting decision and
current policy, and only then calls the same execution/observation path. A
receipt failure transitions the admitted lifecycle to `Quarantined` and returns
`Quarantined` with no runtime state or audit mutation.

`integration::run_with_artifact` requires an accepted artifact whose subject
matches the proposal source digest, then checks a `CustodyRegistry` record
against that artifact's root ID, subject digest, and live raw-retention interval
before admission. Missing, deleted, expired, root-mismatched, or
digest-mismatched custody quarantines before admission or runtime mutation.
These are caller-owned local assertions; the check does not authenticate the
owner, inspect a filesystem, or perform deletion.

`integration::run_with_artifact_and_receipt` composes that pre-admission gate
with the receipt path: custody is checked first, evidence and policy are checked
at admission, the signed capability receipt is verified before capability
consumption, and execution then uses the same rollback and audit path. A
custody rejection leaves both admission and receipt-verifier state untouched.

`integration::run_with_local_artifact_and_receipt` adds a caller-supplied local
custody root and relative artifact path. It verifies the accepted artifact's
manifest root ID and subject digest against the custody record, then checks
the exact file bytes, Unix permissions, path components, and byte limit before
delegating to the artifact-and-receipt workflow. A failed local check
quarantines before admission and receipt verification; the same receipt remains
usable if the caller corrects the artifact and retries. This is a read-only
same-process filesystem check. On Unix, it opens path components relative to
verified directory handles with symlink following disabled and pins the opened
file identity through its handle. It checks filesystem ownership against the
process's effective UID, but does not map that UID to the declared owner or
prevent a process running under that UID from changing filesystem state before
the check. See
[custody-v1.md](custody-v1.md) for its full contract and limits.

`cargo run --bin local_demo` exercises this path with a fixed local proposal
and prints only the workflow disposition and digests.

## Durable local surfaces

`memory::PersistentMemory` stores canonical JSON records under a caller-selected
path. Each write, read, and delete requires an active grant from the shared
`ConsentRegistry`, a matching registered specialist, and a resource scope. The
memory file stores value digests and grant IDs. Open persistent consent state
with `ConsentRegistry::open`; grant and revoke changes reload the latest
canonical snapshot and persist under a local owner-only single-writer lock.
Each `TenantRetrieval` and `PersistentMemory` consent check holds that same lock
through its read or write effect, so a competing revocation waits for an
already-authorized effect to finish and blocks later effects. `ConsentRegistry::save`
is limited to creating an initial snapshot from an in-memory registry; it
cannot overwrite an existing snapshot. The lock fails closed when left behind
by a crashed writer, and an operator must verify no writer is live before
removing it. Persistent memory uses its own per-file lock for each gated read,
write, and delete, and also for `save`; each operation reloads the latest
snapshot while holding that lock. This preserves concurrent cooperating writers across stale handles and
processes. `save` persists and refreshes the latest snapshot; `len` and
`is_empty` expose the handle's last loaded view. Neither file authenticates its
author or prevents rollback to older valid consent bytes. Memory is plaintext
and caller-owned. Memory snapshots are owner-only on Unix, reject
symlinks and broader permissions, and use a synced temporary file plus
parent-directory sync before writes return. Open/recover promotes a validated
pending memory snapshot even when a primary exists. Deletion is logical rather
than secure erasure.

`ReplayJournal`, `KernelSnapshot`, `RuntimeSnapshot`, `audit::AuditJournal`,
`EvidenceRegistry`, `alignment::PredictionLock`, `artifacts::ArtifactRegistry`,
`broker::BrokerJournal`, `contract::FailureBudgetTracker`,
`custody::CustodyRegistry`, `governance::ReleaseRegistry`, both receipt
verifiers, `schema::SchemaRegistry`, `specialist::SpecialistRegistry`, and
`specialist::ToolRegistry` use the shared local persistence helper. Each save
takes a per-path writer lock, creates an exclusive temporary file, syncs its
bytes, atomically replaces the snapshot, and syncs the parent directory. New
files and lock files are mode 0600 on Unix. Recovery takes the same lock,
validates a pending regular file, and promotes it even when a primary exists.
Snapshot loads reject symlink or non-regular primary paths; pending symlinks
are also rejected. An unresolved temporary file blocks a new save until
recovery handles it. These APIs replace complete snapshots: the lock
serializes file replacement, but stale in-memory values do not merge and the
last completed save selects the contents. `AuditJournal` additionally hashes
event metadata and state digests into a canonical chain. This local plumbing
does not provide cross-process append semantics, authenticated authorship, or
rollback protection.

`artifacts::ArtifactRegistry` validates manifest lifecycle records, including
status, timestamp, role, and manifest bindings. Its snapshot recovery follows
the shared locked pending-file rules. This is persistence validation, not proof
of external custody or deletion.

`custody::CustodyRegistry` records an owner-declared external `0700` root,
bounded raw-retention interval, exact artifact digest, validator assertion, and
terminal owner deletion record. The artifact-bound workflow checks the
declared root ID, digest, and logical retention interval before admission.
`claims::ClaimEnvelope` composes evidence by meet only, while
`AggregateReleasePacket` retains claim IDs and evidence digests without raw
payloads. Both remain caller-owned local records.

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

`market::SumJob` accepts one fixed non-negative integer-sum job class and binds
the exact input commitment, output schema, ordinary receipt type, privacy
requirement, price ceiling, deadline, and immutable program identity. Typed
`SumOffer` records bind to the exact job digest, fixed runtime and result
commitment. Selection validates every supplied offer against that job before
choosing by price, provider, and offer ID; one malformed or cross-job offer
rejects the candidate set, and duplicate eligible offer IDs quarantine it.
Well-formed expired offers are excluded from selection.
`SumReceipt` carries the selected offer ID and runtime digest. A separate
verifier recomputes the result, checks program/input/time/price/status bindings,
rejects a repeated receipt digest, and permits one typed
`SettlementProposal` only after local verification. Direct local receipts use
the explicit `local-direct-v1` offer ID; offer-backed settlement requires the
exact offer ID, provider, price, and runtime digest, with completion time
inside the offer's submitted/expires interval. The proposal may be created
after offer expiry while the job remains live. It remains
`AuthorizationRequired`; no payment path exists. The verifier's
verified/reserved sets support canonical caller-owned save/load/recovery. No
provider, wallet, chain, zero-knowledge, FHE, or MPC workload runs.

`governance::ReleaseRegistry` preserves an immutable base and rollback target.
Shadow and canary advances require the candidate's first evidence digest, then a
distinct lowercase digest for the next phase. `freeze` is terminal metadata; it
does not deploy an adapter or authorize an external executor. Registry
snapshots validate candidate identity, phase evidence cardinality, and
canonical bytes before save/load/recovery.

`specialist::SpecialistRegistry` and `specialist::ToolRegistry` use the shared
locked snapshot path. `specialist::ConsentRegistry` uses its purpose-specific
lock-held update path because gated routing, retrieval, and memory operations
must hold the consent lock through their effect. `ConsentRegistry::open`
recovers the current snapshot, and later grant/revoke operations persist while
holding that lock. Consent revocation creates a terminal grant-ID tombstone; a
new issuance has a new digest-bound ID. The registry is shared by routing,
local retrieval, and `PersistentMemory`, so each access rechecks the same
active-grant record. Consent bytes remain plaintext, unauthenticated, and
rollbackable. The tool registry binds tool ID/version, implementation digest and a
canonical manifest-list digest, supports exact invocable lookup, terminal
revocation, and canonical persistence. `TenantRetrieval` stores local records
and checks the shared consent registry on retrieval.
`adapters::AdapterPlan` validates the
shape of an external sandbox/invocation request but rejects external execution
authorization in this foundation slice. `execution_gate::ExecutionGate`
validates a typed sandbox attestation and external job request, then returns a
blocked disposition for every valid request.

## External broker execution slice

`broker::Broker` is the first process-enforced vertical slice after the
same-process foundation. It accepts one typed file transformation over a
`0600` Unix socket, keeps the Ed25519 private key inside the broker process,
binds evidence, executable digest, input digest, scope, quotas, expiry, and
nonce into a durable transaction, and invokes the separate
`capability_supervisor` only after journaling admission and consuming the
single-use kernel capability. The broker rechecks the supervisor's regular-file
digest immediately before launch and rejects symlinks. The supervisor clears
its environment, denies network access, requires a broker-generated launch
token, stages output, and atomically commits only after source and output
validation. A timeout, failed containment, malformed telemetry, or crash
recovery freezes the broker; an in-flight journal record is quarantined and
cannot recreate authority.

`broker_adversarial_runner` and `tests/broker_e2e.rs` provide separate hostile
client and real-process checks. They establish local evidence for authorized
completion, unchanged originals, replay and forged-receipt rejection, direct
supervisor rejection, path validation, malformed child-operation containment,
telemetry freeze, and crash recovery. This evidence is limited to the named
host backend and one operation.

## Remaining execution gates

- Linux host hardening, authenticated process identity, independent replication,
  and a production-grade secret broker; the local launch token is transient
  authority for this one supervisor invocation.
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
