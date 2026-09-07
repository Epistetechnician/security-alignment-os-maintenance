# Kernel V1

State slice: `security-alignment-os-foundation-v1`.

The kernel owns deterministic admission, capability issuance, decision
validation, single-use reservation, policy validation, and the digest-chained
admission journal.
The Rust public interfaces are:

```text
Kernel::admit(proposal, now) -> Decision
Kernel::consume(proposal, decision, now) -> bool
Kernel::complete/rollback/quarantine/freeze/kill(proposal) -> bool
KernelSnapshot::save/load/recover(path)
ReplayJournal::save(path) / load(path) / recover(path)
```

An accepted decision is valid only when its private issuance record matches the
full current candidate digest, complete capability token, complete decision
digest, current policy digest, issuance window, and claim-bounded expiry.
Decision records are transport values; constructing one directly does not issue
authority. `Kernel::consume` reserves the token once in the kernel, so
runtime instances sharing a kernel cannot replay it. A runtime must call this
method immediately before its own reversible mutation and mutate state only
after a successful result.

Malformed or later-mutated policy state is rejected before admission or
consumption. Candidate payloads remain caller-owned and may be mutable. A mutation after
admission changes the candidate digest and invalidates the issued decision.
Issued token budgets and policy ceilings are snapshotted into immutable
mappings. Budget checks are performed before broker state changes, including
for rejected over-budget and malformed uses. Zero-cost use is still single-use.

Every journaled proposal also receives a lifecycle record. Accepted admission
transitions `Proposal -> Admitted`, successful capability consumption requires
`Admitted` and transitions to `Executing`, and the coordinator must record
`Complete`, `Rollback`, `Freeze`, or `Kill` through the same kernel state
machine. A frozen or killed lifecycle cannot consume a capability, including
from another runtime instance sharing the kernel.

Admission rejects non-integer resource values and timestamps, uppercase or
malformed SHA-256 digests, stale required claims, and required claims that
explicitly exclude their own guarantee. Capability use requires
`issued_at <= now < expires_at`; backward-clock use before issuance and use at
or after expiry are invalid.

The journal persists canonical JSON with SHA-256 chain entries. Loading requires
canonical bytes, contiguous sequence numbers, lowercase digest fields, a valid
previous-digest chain, unique candidate digests, and a matching candidate
index. Persistence is caller-owned local file plumbing: it does not provide
cross-process locking, authenticated storage, signatures, OS enforcement,
process isolation, network control, or a trusted clock. Reviewer and agent
identities are local role assertions. The kernel does not authenticate model
output, prove semantic correctness, establish alignment, or grant provider or
financial authority.

`recover(path)` promotes the canonical temporary snapshot only when the primary
path is absent, covering a crash between temporary write and atomic rename. A
present but malformed primary remains an error and is never silently replaced.
The runtime uses the same rule through `RuntimeSnapshot::recover_snapshot`,
binding state, checkpoints, shutdown flags, and the audit chain together.
`KernelSnapshot` persists the policy, journal, and lifecycle records only;
private capability issuances are intentionally not serialized, so a restarted
kernel cannot recreate authority from an accepted decision alone.

Validation performed for this lane:

```text
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

These are local regression checks, not independent acceptance or production
security evidence.
