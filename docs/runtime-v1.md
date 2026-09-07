# Runtime lane V1

State slice: `security-alignment-os-foundation-v1`.

`Runtime` is a local reference executor. `execute` accepts only `Read` and
`Write`, validates the decision's candidate, agent, action, scope, intent and
budget bindings, validates write keys before capability consumption, and then
commits one reversible dictionary transition. Every successful action records a
checkpoint. `rollback` restores the latest checkpoint while retaining consumed
authority. `freeze` stops execution and rollback; `kill` also marks the runtime
killed. Audit records contain operation metadata and state digests, not values.

`SpecialistRegistry` serves immutable `SpecialistIdentity` records and refuses
identity drift. Revocation is explicit and permanent for a registered ID.
Identity snapshots validate key bindings and use canonical save/load/recovery;
the role and identity fields remain caller assertions.
`TenantRetrieval` stores local records under `(tenant, resource)` and requires a
registered, non-revoked specialist plus an active, resource-scoped
`ConsentGrant`. `memory::PersistentMemory` adds canonical caller-owned file
persistence with the same checks and a digest for each value.

`ToolRegistry` binds tool ID/version, implementation digest and a canonical
sorted manifest-list digest. `freeze` captures the list digest and
`check_drift` detects later mismatch. `require_invocable` requires an exact
manifest digest, while terminal `revoke` blocks future lookup and marks a
frozen list as drifted. Registry snapshots validate lifecycle data and use
canonical save/load/recovery. Tool manifests are contracts only; this lane
never invokes tools. `RedactedTelemetry` recursively removes sensitive fields
such as credentials, tokens, prompts, payloads and content before retention.

`integration::run` composes evidence validation, admission, execution and
caller-supplied health/telemetry observations. An unhealthy observation rolls
back and freezes after a successful local transition. The observation is an
assertion supplied by the caller, not host telemetry.

These are local Rust controls. They do not establish authenticated identity,
OS/container isolation, process confinement, network policy, model execution,
provider execution, or production security. External sandbox and provider work
remains blocked in the foundation slice.
