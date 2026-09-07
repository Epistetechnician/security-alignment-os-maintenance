# Versioned schema registry V1

State slice: `security-alignment-os-foundation-v1`.

`schema::SchemaDescriptor` binds a caller-supplied schema identifier and
positive version to one lowercase SHA-256 digest. `schema::SchemaRegistry`
registers each `(schema_id, version)` once and `require` demands an exact
identifier, version, and digest match before a cross-module record may use the
schema. `validate` rechecks map-key bindings and descriptor shape. `save`,
`load`, and `recover` use canonical JSON and a temporary-file promotion path;
malformed or noncanonical snapshots are rejected.

The registry is immutable after registration at each identity. It is local
caller-owned data: it does not parse schemas, retrieve definitions, authenticate
the publisher, prove that a producer followed the schema, or provide a
distributed registry. Missing, malformed, duplicate, or digest-mismatched
identities fail closed.

Validation:

```text
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Passing checks establish a local schema-binding contract only.
