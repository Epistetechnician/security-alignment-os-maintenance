# Local maintenance workflow V1

State slice: `security-alignment-os-foundation-v1`.

This contract is a bounded, single-file maintenance proposal. The proposal
contains one safe relative path, exact before and after bytes, and SHA-256
digests of both byte strings. It also freezes the evaluator executable, input,
test-suite, and policy digests, plus a non-empty exact test roster. The roster
must include `evidence-substitution`, `evidence-expiry`, `path-escape`, and
`failed-postcheck-rollback`; every listed test must have one passing result.

The coordinator is constructed with the frozen requirements and expected
evaluator and reviewer role assertions. A packet must repeat those exact
requirements, and its evaluator output must bind directly to the proposal
digest. The packet carries the complete test results. A separate acceptance
record contains the SHA-256 digest of the complete proposal/evaluation packet.
The workflow recomputes that digest before any mutation and requires distinct
proposer, evaluator, and reviewer role assertions. These role strings are
metadata supplied by the caller. They are not authenticated identities or
proof of independence.

Time is supplied by the caller and checked at admission only. Replay and freeze
state are process-local; restarting or reconstructing the coordinator does not
preserve them. The executor trait is trusted and is not an isolation boundary.
Broker integration must supply authenticated identities, a trusted live clock,
lease enforcement throughout execution, and durable replay/freeze state before
this workflow can authorize real checkout changes.

The coordinator quarantines missing, expired, malformed, substituted, or
mismatched evidence and rejects acceptance replay within that coordinator. It
reads the target through `MaintenanceExecutor`, verifies the exact before
bytes, consumes the acceptance, writes the exact after bytes, and performs an
exact postcheck. A failed postcheck attempts to restore the before bytes and
reports `RolledBack`; a failed restoration reports and latches `Frozen`, so the
coordinator rejects later packets. Acceptance remains consumed after either
outcome, so a failed attempt cannot be replayed.

`InMemoryMaintenanceExecutor` is the only implementation supplied here. It is
for hermetic contract tests and performs no filesystem, subprocess, model, or
network operation. An executor implementation elsewhere would need its own
reviewed local-scope and durability contract. This module does not add generic
broker patch support: the current external broker remains limited to its
existing `UppercaseAscii` operation. The workflow is local contract evidence,
not production enforcement, authenticated independent evaluation, or a claim
of safe arbitrary repository mutation.
