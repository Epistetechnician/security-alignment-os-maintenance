# Separate-host maintenance replication contract V1

State slice: `security-alignment-os-foundation-v1`.

This is the next gate after the fixed maintenance process. It defines a
digest-bound, signed packet for two independently produced reports about the
same fixed operation. It does not launch a second host, transfer evidence, or
authenticate a host or human operator.

## Packet binding

`maintenance_replication::ReplicationPacket` accepts exactly two
`HostReport` values. Each report must bind:

- the fixed operation identity, current process version, and one exact
  implementation revision;
- the same request digest and full-checkout baseline digest;
- the same evaluator executable, input, test, policy, evaluator-key, and
  timeout bindings;
- a non-empty host label, a distinct operator label, and distinct Ed25519 host
  and operator keys;
- all eight required scenario results, in the fixed order;
- an immutable replication claim ceiling;
- a report identity digest and host/operator signatures over the complete
  report identity.

The packet sorts reports by host label, requires distinct host/operator/key
identities, and carries its own digest-bound packet identity. Canonical JSON is
required on the wire. Re-serialization equality rejects duplicate-key and
formatting variants before validation can observe a collapsed JSON object.
The packet binds evaluator requirement digests and timeout, but does not inspect
the evaluator executable or establish its custody.

## Required reproduction matrix

| Scenario | Required terminal result | Required final checkout relation |
| --- | --- | --- |
| `authorized-completion` | `Applied` / `AuthorizedChangeCommitted` | differs from the authorized baseline |
| `evaluation-expiry` | `Quarantined` / `NoMutation` | equals the authorized baseline |
| `pre-finalization-cancellation` | `RolledBack` / `BaselineRestored` | equals the authorized baseline |
| `pre-finalization-expiry` | `RolledBack` / `BaselineRestored` | equals the authorized baseline |
| `concurrent-target-change` | `Frozen` / `ExternalChangePreservedAndFrozen` | differs from the authorized baseline |
| `neighbor-change-recovery` | `Frozen` / `ExternalChangePreservedAndFrozen` | differs from the authorized baseline |
| `shared-checkout-lock` | `Blocked` / `NoMutation` | equals the authorized baseline |
| `replacement-lock-ownership` | `Blocked` / `NoMutation` | equals the authorized baseline |

Each scenario also carries a digest of the local reproduction evidence. The
packet does not carry raw logs or claim that the digest names authenticated
custody. Changing a scenario result or evidence digest after signing invalidates
the report identity or signature.

## Reproduction boundary

An actual replication requires two operators on separate hosts to run the
already reviewed fixed process from the same exact implementation revision,
against the same frozen request and requirements. Each operator records the
scenario result and evidence digest, signs its own report with a distinct key,
and exchanges only the packet required by the local acceptance procedure.

The current repository provides the Rust packet validator and deterministic
contract tests. It does not provide host attestation, authenticated operator
identity, network transfer, evidence custody, or a second-host execution
result. The local two-report fixture is a wire-contract test, not separate-host
replication evidence.

## Validation

```text
cargo test --test maintenance_replication
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
pnpm run lint
```

The claim ceiling remains local Rust consistency evidence for this fixed
operation. Adaptation, model execution, provider execution, execution markets,
and settlement remain outside this state slice.
