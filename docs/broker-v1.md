# External capability broker V1

State slice: `security-alignment-os-foundation-v1`.

This slice is the first process-enforced execution path. An agent sends one
typed `FileTransformRequest` over a `0600` Unix-domain socket. The broker
loads evidence, recomputes the proposal digest, checks the exact supervisor
binary digest, admits the proposal through the existing kernel, and issues a
single-use Ed25519 capability receipt. The private signing key is generated
inside the broker process and is never accepted from or returned to the
client. The client receives only the public issuer key in `Hello` and the
receipt after admission.

The only operation is `TrimTrailingAsciiSpaces` over one unlinked regular
root-level `.md` source and destination file in the canonical broker workspace.
Paths must be relative, contain only normal path components, and remain inside
the workspace. The evaluator removes ASCII spaces immediately before LF or
CRLF line endings and at EOF while preserving tabs and all other bytes. The
source digest, byte quota, executable digest, scope, request nonce, and
expiry are bound into the proposal and transaction records. Network and
ambient environment variables are denied to the supervisor. The supervisor
also requires a broker-generated one-time launch token in its cleared
environment; direct invocation of the supervisor therefore fails before it
can stage output.

On successful completion the broker returns both the pre-execution
`CapabilityReceipt` and a post-validation `ExecutionReceipt`. The latter is
signed by the same broker-only key and binds the capability receipt ID,
decision digest, evidence ID and evidence record digest, input digest,
operation ID, output digest, and expiry. A client can verify this result with
`ReceiptVerifier::verify_execution`
or the independent `checker::validate_execution_receipt` without recreating
the broker's private key or trusting an unsigned output message.

The broker journal is canonical, hash chained, and atomically replaced. It
records `Admitted` before `Executing`, then `Committed`, `RolledBack`, or
`Quarantined`. A restart converts any latest admitted or executing transaction
to `Quarantined`, marks the journal frozen, and never reconstructs a consumed
kernel issuance. The broker continues serving `Frozen` responses so callers
can observe containment. The independent checker replays the hash chain,
transaction transitions, request identity continuity, and agent/nonce replay
constraints from the persisted bytes.

The broker binds the configured Unix socket before serving. A second broker
using the same socket is rejected as an occupied state lock; a socket left by
a crashed broker is removed only after a live connection check fails. This
serializes writers for one configured checkout while retaining explicit
same-UID and compromised-host nonclaims.

The supervisor writes a create-new staging file, syncs it, rechecks the source
digest and destination absence, and atomically renames the staged bytes. The
broker independently rechecks the original source and committed output. A
timeout, cancellation, failed supervisor, changed source, invalid output, or
journal failure removes the destination when possible, records rollback, and
freezes further admission. Cancellation checkpoints cover admission, completed
evaluation, pre-replacement staging, and post-replacement handling. On macOS
the backend uses `/usr/bin/sandbox-exec`
with network and
file-write denial plus an exact supervisor executable allowance. On Linux it
uses an unprivileged user, network, and PID namespace through `unshare`; if
that primitive is unavailable the request fails closed. The Linux invocation
also uses `--kill-child=KILL`, so terminating the namespace wrapper terminates
the supervised process tree.

`broker_adversarial_runner` is a separate Rust client. It checks direct
supervisor invocation without a launch token, path escape, replay, forged
receipt signature, malformed child-operation input, and missing-telemetry
freeze. `tests/broker_e2e.rs` starts real broker and supervisor processes and
checks successful transformation, unchanged source bytes, receipt forgery
rejection, replay rejection, freeze behavior, and crash recovery from an
`Executing` journal record.

For a stable local test identity, the broker accepts an optional owner-only
seed path as its sixth argument. The file must contain exactly 32 bytes and
have no group or other permission bits; the broker never prints or returns the
seed. Production deployment still requires an externally managed key and
authenticated process identity.

This is local enforcement evidence for one operation on the supported host.
It does not establish authenticated host identity, protection from a hostile
same-UID process that can inspect the workspace, provider execution, model
alignment, cryptographic proof of input truth, distributed replay protection,
or production readiness. Linux remains the practical deployment target;
macOS is a development backend whose Seatbelt availability and policy behavior
must be revalidated on each supported OS release.

## Commands

```sh
cargo run --bin capability_broker -- <socket> <workspace> <journal> <evidence.json> <capability_supervisor> [broker_seed]
cargo run --bin broker_adversarial_runner -- <socket> <request.json> <workspace> <capability_supervisor>
```
