# Fault injection v1

State slice: `security-alignment-os-foundation-v1`.

`src/faults.rs` is a Rust-only fault-injection module exported by the crate.
The harness uses only local pure-data APIs and emits `FaultOutcome` records
containing a scenario, a fail-closed disposition, and SHA-256 digests. It does
not emit journal bytes, proposal payloads, private values, process output, or
provider data.

The deterministic scenarios are:

| Scenario | Required disposition | Boundary exercised |
| --- | --- | --- |
| `replay` | `Rejected` | Duplicate proposal cannot append a second replay-journal entry. |
| `stale_clock` | `Rejected` | An expired capability fails before runtime state or audit mutation. |
| `stale_policy_digest` | `Rejected` | A policy change after admission is detected before execution. |
| `malformed_journal_bytes` | `Quarantined` | Noncanonical, malformed, or tampered journal bytes fail through `ReplayJournal::load`. |
| `partial_write` | `RolledBack` | The latest runtime checkpoint restores the pre-write state digest. |
| `kill_freeze_observation` | `Frozen` | An unhealthy or kill observation rolls back the action and closes the runtime. |

The stale-policy scenario exercises `Kernel::consume` directly. Consumption
recomputes the current policy digest and rejects a decision issued under an old
policy before runtime state can change.

The tests are hermetic and local:

```text
cargo test --test faults
cargo fmt --all -- --check
```

These checks establish local fail-closed behavior only. They do not prove an
OS-level kill path, process isolation, network egress enforcement, durable
crash recovery, authenticated identity, provider execution, or production
readiness.
