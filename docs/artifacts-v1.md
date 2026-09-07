# Artifact manifests and evidence lifecycle V1

State slice: `security-alignment-os-foundation-v1`.

`artifacts.rs` is the local evidence-plane boundary. `ArtifactManifest`
requires a stable artifact identifier, lowercase SHA-256 digests for the exact
subject, source, and provenance records, a caller-declared license, a custody
root, and a finite half-open retention interval. `validate()` rejects missing
fields, control characters, malformed digests, and non-positive retention
intervals. The manifest digest is computed from the validated canonical Rust
serialization.

`ArtifactRegistry` has three monotonic local states:

```text
quarantined -> accepted -> revoked
       \-----------------> revoked
```

Quarantine requires distinct non-empty operator and validator role assertions.
Acceptance requires the record to remain quarantined and within its retention
interval, an exact subject-digest match supplied at review time, and a
non-empty reviewer assertion distinct from both earlier roles. Revocation also
requires the exact subject digest and is terminal for the record.

`is_valid` and `require_valid` require accepted status, a live retention
interval, the exact subject digest, and all three distinct role assertions.
Duplicate artifact identifiers, repeated acceptance, repeated revocation, and
subject mismatches fail closed.

`ArtifactRegistry::validate` rechecks every persisted lifecycle record,
including status/timestamp consistency and role separation. `save` writes a
canonical JSON snapshot through a temporary path; `load` rejects non-canonical
or invalid bytes; `recover` promotes a valid temporary snapshot only when the
primary path is absent. The path and filesystem remain caller-owned.

This is local pure-data evidence only. Role strings are caller assertions; the
module does not authenticate identities, provide signatures, verify a custody
filesystem, prove license ownership, enforce retention deletion, inspect
artifact bytes, or establish an external or scientific claim. No provider,
model, network, settlement, or production execution is involved.

Focused validation:

```text
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Every change belongs to state slice
`security-alignment-os-foundation-v1`.
