# Deterministic property checks V1

State slice: `security-alignment-os-foundation-v1`.

`src/property.rs` provides a local regression surface for the Phase 0
contract. It does not authenticate identities, run a process, enforce an
operating-system sandbox, contact a provider, execute a model, or establish
alignment evidence.

## Checks

The lifecycle check independently enumerates every pair in the fixed table:
9 states x 8 events = 72 cases. It verifies both the returned transition and
the `Lifecycle::apply` mutation contract: valid transitions advance the
revision, while invalid transitions leave state and revision unchanged.

The authority check enumerates all 256 elements of the eight-atom powerset and
all 65,536 ordered pairs. It verifies set encoding, subset order, `covers`,
union, and intersection. A separate check evaluates all 56 ordered pairs of
distinct singleton authorities and fails if either singleton covers the other.

The kernel checks exercise local public APIs for three control-plane
invariants:

- a rejected proposal cannot mutate runtime state or audit records;
- an expired capability cannot execute or mutate runtime state/audit records;
- a killed runtime rejects execution before kernel capability consumption.

## Digest-only records

`PropertyOutcome` contains a stable property identifier, pass/fail status, and
an evidence digest. `CheckReport` contains the fixed state-slice identifier,
the outcomes, counters, and a report digest. The records do not retain the
proposal, capability, payload, state map, journal bytes, or raw mismatch data.
`CheckReport::validate` recomputes the public counters and report commitment.

The coordinator exports the module from `src/lib.rs`, so these checks are part
of the crate gate.

## Validation

Run:

```text
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Passing these checks establishes deterministic local regression evidence only.
It is not a formal proof, model-checked result, independent validator
identity, external kill guarantee, OS-level containment result, provider
receipt, cryptographic proof of input truth, or production-readiness claim.
