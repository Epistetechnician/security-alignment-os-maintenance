# Kernel V1

State slice: `security-alignment-os-foundation-v1`.

The kernel owns deterministic admission, capability issuance, decision
validation, single-use reservation, and the digest-chained admission journal.
The Rust public interfaces are:

```text
Kernel::admit(proposal, now) -> Decision
Kernel::consume(proposal, decision, now) -> bool
ReplayJournal::save(path) / load(path)
```

An accepted decision is valid only when its private issuance record matches the
full current candidate digest, complete capability token, complete decision
digest, current policy digest, issuance window, and claim-bounded expiry.
Decision records are transport values; constructing one directly does not issue
authority. `Kernel::consume` reserves the token once in the kernel, so
runtime instances sharing a kernel cannot replay it. A runtime must call this
method immediately before its own reversible mutation and mutate state only
after a successful result.

Candidate payloads remain caller-owned and may be mutable. A mutation after
admission changes the candidate digest and invalidates the issued decision.
Issued token budgets and policy ceilings are snapshotted into immutable
mappings. Budget checks are performed before broker state changes, including
for rejected over-budget and malformed uses. Zero-cost use is still single-use.

Admission rejects non-integer resource values and timestamps, uppercase or
malformed SHA-256 digests, stale required claims, and required claims that
explicitly exclude their own guarantee. Expiry is exclusive: execution at or
after the token or claim expiry is invalid.

The journal persists canonical JSON with SHA-256 chain entries. Loading requires
canonical bytes, contiguous sequence numbers, lowercase digest fields, a valid
previous-digest chain, unique candidate digests, and a matching candidate
index. Persistence is caller-owned local file plumbing: it does not provide
cross-process locking, authenticated storage, signatures, OS enforcement,
process isolation, network control, or a trusted clock. Reviewer and agent
identities are local role assertions. The kernel does not authenticate model
output, prove semantic correctness, establish alignment, or grant provider or
financial authority.

Validation performed for this lane:

```text
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

These are local regression checks, not independent acceptance or production
security evidence.
