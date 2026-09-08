# Separate-host maintenance replication contract V1

State slice: `security-alignment-os-foundation-v1`.

This is the next gate after the fixed maintenance process. It defines a
digest-bound, signed packet for two independently produced reports about the
same fixed operation. It does not launch a second host, transfer evidence, or
authenticate a host, a human operator, or evidence custody.

## Packet binding

`maintenance_replication::ReplicationPacket` carries the exact values that
both hosts must independently reproduce:

- the fixed operation identity, process version, and exact source revision;
- a digest of the canonical `rustc -Vv` toolchain record;
- the canonical request bytes, including the fixed path, before/after bytes,
  all request digests, nonce, lease, and checkout baseline digest;
- an ordered manifest of every regular file in the checkout, with canonical
  relative path, byte length, content digest, regular-file kind, and link
  count;
- evaluator executable, input, test, policy, evaluator-key, and timeout
  bindings;
- the two signed host reports and the immutable claim ceiling.

The manifest uses the same scope as the maintenance process baseline digest:
regular-file paths and bytes. Directories, symlinks, hardlinks, and special
files are not silently represented as regular files; the process rejects them,
and the relevant negative scenario must record that rejection. A host must
recompute the manifest and compare it with both the packet manifest digest and
the checkout baseline digest before treating the bundle as reproduced. The
packet only proves that the supplied request and manifest bytes are internally
consistent; it cannot inspect a host checkout.

Each report must bind:

- a non-empty host label, a distinct operator label, and distinct Ed25519 host
  and operator keys;
- all 20 required scenario results, in fixed order, including role,
  invocation status, recovery status where applicable, initial/final checkout
  digests, recovery disposition, and evidence digest;
- an immutable replication claim ceiling;
- a report identity digest and host/operator signatures over the complete
  report identity.

The packet sorts reports by host label, requires distinct host/operator/key
identities, and carries its own digest-bound packet identity. Canonical JSON is
required on the wire. Re-serialization equality rejects duplicate-key and
formatting variants before validation can observe a collapsed JSON object.
The packet binds evaluator and toolchain digests but does not inspect their
bytes or establish their custody.

## Required reproduction matrix

| Scenario | Required terminal result | Required final checkout relation |
| --- | --- | --- |
| `authorized-completion` | `Applied` / `AuthorizedChangeCommitted` | final differs from baseline |
| `replay-after-completion` | `Quarantined` / `AlreadyAppliedPreserved` | already-applied state is unchanged and differs from baseline |
| `invalid-or-stale-baseline` | `Quarantined` / `NoMutation` | final equals baseline |
| `pre-admission-expiry` | `Quarantined` / `NoMutation` | final equals baseline |
| `pre-admission-cancellation` | `Quarantined` / `NoMutation` | final equals baseline |
| `evaluator-requirement-substitution` | `Quarantined` / `NoMutation` | final equals baseline |
| `path-escape` | `ProcessError` / `NoMutation` | final equals baseline |
| `link-escape` | `ProcessError` / `NoMutation` | final equals baseline and outside target is unchanged |
| `evaluation-expiry` | `Quarantined` / `NoMutation` | final equals baseline |
| `pre-finalization-cancellation` | `RolledBack` / `BaselineRestored` | final equals baseline |
| `pre-finalization-expiry` | `RolledBack` / `BaselineRestored` | final equals baseline |
| `crash-after-durable-intent` | initial `ProcessError`; recovery `Frozen` / `BaselineRestored` | recovery final equals baseline |
| `crash-after-replacement` | initial `ProcessError`; recovery `Frozen` / `BaselineRestored` | recovery final equals baseline |
| `concurrent-target-change` | `Frozen` / `ExternalChangePreservedAndFrozen` | external change differs from baseline and is preserved |
| `completion-state-persistence-failure` | initial `ProcessError`; recovery `Frozen` / `BaselineRestored` | recovery final equals baseline |
| `neighbor-change-recovery` | `Frozen` / `ExternalChangePreservedAndFrozen` | external neighbor change differs from baseline and is preserved |
| `occupied-lock` | `ProcessError` / `NoMutation` | final equals baseline |
| `cross-state-directory-lock-contention` (winner) | `Applied` / `AuthorizedChangeCommitted` | final differs from baseline |
| `cross-state-directory-lock-contention` (contender) | `Blocked` / `NoMutation` | final equals baseline |
| `replacement-lock-ownership` (winner) | `Applied` / `AuthorizedChangeCommitted` | authorized change is committed and replacement lock remains owned |
| `recovery-config-redirect` | `ProcessError` / `AlternateCheckoutPreserved` | redirected checkout remains its own initial state |

The packet requires exactly one winner and one contender for the cross-state
directory-lock scenario. Replacement-lock ownership is an authorized winner
case: cleanup must not remove a lock file that replaced the process’s original
lock. Each scenario also carries a digest of local reproduction evidence. The
packet does not carry raw logs or claim that an evidence digest names
authenticated custody. Changing a scenario result or evidence digest after
signing invalidates the report identity or signature.

## Reproduction boundary

An actual replication requires two operators on separate hosts to run the
already reviewed fixed process from the same exact implementation revision,
toolchain, frozen request, and requirements. Each operator must independently
recompute the checkout manifest, evaluator executable digest, and toolchain
digest; run the full scenario matrix; record raw evidence in private custody;
and sign its own report with an out-of-band authenticated host/operator key.
Only packet digests and signed reports are exchanged for acceptance.

The current repository provides the Rust packet validator,
`maintenance_replication_verifier`, and deterministic contract tests. The
verifier emits `status: valid_local_packet` with `verdict: Inconclusive`, not a
replication pass. It does not provide
trusted host or operator roots, hardware or OS attestation, authenticated key
custody, evidence custody, network transfer, or a second-host execution
result. Labels, signatures, and distinct keys are caller assertions until an
external operator and host-attestation procedure authenticates them. Missing
or unverifiable external evidence is `Inconclusive`, never pass.

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
