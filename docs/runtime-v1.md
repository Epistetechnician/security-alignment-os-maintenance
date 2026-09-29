# Runtime lane V1

State slice: `security-alignment-os-foundation-v1`.

`Runtime` is a local reference executor. `execute` accepts only `Read` and
`Write`, validates the decision's candidate, agent, action, scope, intent and
budget bindings, validates write keys before capability consumption, and then
commits one reversible dictionary transition. Every successful action records a
checkpoint. `rollback` restores the latest checkpoint while retaining consumed
authority. `freeze` stops execution and rollback; `kill` also marks the runtime
killed. Repeated freeze/kill calls do not append duplicate shutdown events.
Audit records contain operation metadata and state digests, not values.
Shutdown and rollback reasons are retained only as digests, never as raw text.
`RuntimeSnapshot` persists state, checkpoints, shutdown flags, and audit records
as canonical JSON. `ReplayJournal`, `KernelSnapshot`, `RuntimeSnapshot`, and
`AuditJournal` serialize snapshot replacement with a per-path local writer lock,
write a synced temporary file mode 0600 on Unix, and sync the parent directory
after replacement. Recovery validates and promotes a pending temporary snapshot
even when a primary exists. Snapshot loads reject symlink or non-regular
primary paths, and recovery rejects pending symlinks. These are complete
snapshot replacements: writers do not merge stale in-memory snapshots, so the
last completed save selects the state.
If a pending temporary file exists, a new save fails closed until recovery
validates and resolves it.
The persisted audit schema allowlists the event field plus candidate, decision,
policy, capability-token, state, and shutdown-reason digests; unknown fields,
raw text fields, and malformed digest values fail closed before persistence.

`SpecialistRegistry` serves immutable `SpecialistIdentity` records and refuses
identity drift. Revocation is explicit and permanent for a registered ID.
Identity snapshots validate key bindings and use the shared locked save/recovery
path; the role and identity fields remain caller assertions.
`TenantRetrieval` stores local records under `(tenant, resource)` and requires a
registered, non-revoked specialist plus an active, resource-scoped
`ConsentGrant` registered in the shared `ConsentRegistry`. Use
`ConsentRegistry::open` for persistent operation: grant and revoke reload the
latest canonical snapshot under a local owner-only writer lock, and gated
retrieval and memory effects hold the lock through the operation. Recovery
promotes a validated pending snapshot after an interrupted atomic replace.
`ConsentRegistry::save` only creates a missing initial snapshot from an
in-memory registry. `memory::PersistentMemory` adds caller-owned canonical file
persistence and a digest for each value. The consent lock serializes consent
updates and gated effects, but does not authenticate snapshot authors or stop a
caller from restoring older valid bytes. On Unix, memory snapshots are
owner-only and reject symlinks or broader permissions. Writes sync a temporary
snapshot and its parent directory; recovery promotes a valid pending snapshot
even when a primary exists. A per-memory-file lock serializes each gated
read/write/delete and `save`; each operation reloads the latest snapshot while
holding the lock, preserving updates from cooperating concurrent handles and
processes. `save` persists and refreshes its handle, while `len` and `is_empty`
report the handle's last loaded view. An abandoned lock fails closed and requires operator
inspection before removal.

`routing::RoutingRequest` and `RoutingDecision` provide a digest-only routing
seam for the first product wedge. A caller selects a registered specialist;
the route is accepted only while the exact tenant consent grant remains in the
shared `ConsentRegistry` and the specialist identity is active. The
decision binds the exact input digest, grant, tenant, specialist identity
digest, and expiry window. Validation rechecks the consent store, so revocation
blocks an existing decision. The seam does not classify raw prompts or invoke
a model.
Its issuance time must also be no earlier than the request and consent-grant
issuance times, preventing pre-consent decision replay.

`ToolRegistry` binds tool ID/version, implementation digest and a canonical
sorted manifest-list digest. `freeze` captures the list digest and
`check_drift` detects later mismatch. `require_invocable` requires an exact
manifest digest, while terminal `revoke` blocks future lookup and marks a
frozen list as drifted. Registry snapshots validate lifecycle data and use the
shared locked save/recovery path. Tool manifests are contracts only; this lane
never invokes tools. `RedactedTelemetry` recursively removes sensitive fields
such as credentials, tokens, prompts, payloads and content before retention.

`integration::run` composes evidence validation, admission, execution and
caller-supplied health/telemetry observations. An unhealthy observation rolls
back and freezes after a successful local transition. Runtime shutdown events
are one-way; repeated freeze/kill requests do not create duplicate audit
mutations. The observation is an assertion supplied by the caller, not host
telemetry.

These are local Rust controls. They do not establish authenticated identity,
OS/container isolation, process confinement, network policy, model execution,
provider execution, or production security. External sandbox and provider work
remains blocked in the foundation slice.
