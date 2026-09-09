# Maintenance replication runner V1

State slice: security-alignment-os-foundation-v1.

The Rust maintenance_replication_runner is the host-side producer for the
fixed maintenance replication contract. It executes the real
maintenance_broker binary for each required scenario in an isolated checkout,
records raw process evidence in private caller-owned storage, and signs one
HostReport. It does not contact another host, transfer evidence, authenticate
host or operator identity, or raise the claim ceiling beyond local evidence.

## Workflow

Build the binaries with the repository's reproducible Apple linker setting, then
provision an operator-owned private checkout containing
the fixed Markdown operation. The following commands use absolute paths:

~~~text
maintenance_replication_runner keygen KEY_DIR
maintenance_replication_runner keygen-evaluator KEY_DIR
maintenance_replication_runner keygen-host KEY_DIR
maintenance_replication_runner init CHECKOUT ARTIFACT_DIR BROKER EVALUATOR EVALUATOR_SEED HOST_ID OPERATOR_ID HOST_SEED OPERATOR_SEED IMPLEMENTATION_REVISION LEASE_EXPIRES_AT NONCE CONTENTION_ROLE SPEC_OUTPUT
maintenance_replication_runner report SPEC_OUTPUT
maintenance_replication_runner packet FROZEN_BUNDLE REPORT_A REPORT_B PACKET_OUTPUT
~~~

On aarch64 macOS, the checked-in Cargo target configuration passes `-reproducible`
to Apple `ld64`. This is part of the evaluator build binding: independent
operators must build from the same source revision with the approved Rust and
Apple toolchains, and the evaluator executable bytes must match exactly. The
`maintenance_reproducibility` integration test performs two clean release
builds in isolated target directories and rejects any byte or SHA-256 digest
difference.

keygen is a convenience for single-operator local setup and creates owner-only
evaluator, host, and operator seed files. `keygen-evaluator` creates only the
evaluator seed, while `keygen-host` creates only the host and operator seeds.
Use the scoped commands when evaluator custody and Host B operator custody are
administered separately. The evaluator authority must provision the same
evaluator seed to both hosts through its authenticated custody procedure; Host
A and Host B must not copy evaluator, host, or operator seeds to one another.
Independent operators must generate and retain their own host and operator keys
independently. init
freezes the request and complete baseline manifest into the runner
specification. The implementation revision is an operator-supplied, exact
40-character lowercase revision binding and must be checked against the source
and executable provenance out of band.

report creates ARTIFACT_DIR/cases/ with one private isolated case per scenario,
ARTIFACT_DIR/evidence/ with one canonical raw evidence record per scenario, and
ARTIFACT_DIR/report.json. Any unexpected terminal status, digest relation,
signature, or recovery result aborts report creation. Crash scenarios remove a
stale lock only after the child process has exited; this is the
operator-authorized recovery action defined by the process contract.

packet accepts two independently exchanged canonical reports and the same
frozen bundle, validates all bindings and signatures, and writes a canonical
packet. The command reports valid_local_packet with verdict Inconclusive. A
same-machine rehearsal can exercise packet plumbing, but it is not separate
host replication or authenticated independent evidence.

The runner uses the process's operator-only deterministic failpoints to
reproduce crash, cancellation, expiry, contention, and replacement-lock
scenarios. Those controls are test harness inputs; they do not grant authority
and must not be used to represent an operational maintenance request.

## Host B handoff checklist

Host B is not created by this repository. Before accepting its report, the
external operator must authenticate all of the following out of band:

- Host B is a Linux system independently administered from Host A, with a
  distinct operator identity and separate private custody for its checkout,
  evaluator seed, host/operator seeds, and raw evidence.
- Host B checks out the exact implementation revision and independently
  recomputes the toolchain digest, evaluator executable digest, frozen request
  digest, and baseline manifest digest.
- Host B runs all 20 scenarios with the same frozen bundle, evaluator public
  key, evaluator inputs/tests/policy, process version, lease, and nonce.
- Only the canonical frozen bundle and signed `report.json` are exchanged for
  packet assembly. Seeds and raw evidence remain with their original custodians.

Distinct labels and signatures in a packet are insufficient to authenticate
these properties. If any checklist item is unavailable or unverifiable, the
packet remains `Inconclusive`.

## Boundary

The packet still requires two independently administered hosts, distinct
operators, separate evaluator and signing-key custody, matching source,
toolchain, evaluator, request, and manifest digests, and authenticated
out-of-band evidence review. Tailscale or another transport can carry the
exchange but does not establish those properties. Missing external
authentication remains Inconclusive, never pass.
