# Independent replication packet V1

State slice: `security-alignment-os-foundation-v1`.

`replication::FrozenReplicationPacket` is the immutable handoff for a second
operator. It binds the source revision, toolchain, configuration, test
manifest, original maintenance request, expected terminal state, output,
rollback, untouched-neighbor, receipt-binding, recovery-freeze digests, host
prerequisites, retention deadline, and the claim ceiling
`ReplicatedBoundedMaintenanceExecution`. Raw payloads are prohibited.

`ReplicationResult` contains only the second operator and host assertions plus
the exact terminal and digest observations. `ReplicationSigner` signs the
canonical result bytes. `compare` verifies the pinned key and then requires an
exact match to the frozen packet; any mismatch returns quarantine. The signer
and host identifiers are caller-supplied assertions. They do not authenticate
an operator, host, or independent scientific validator.

Packets and signed results use canonical JSON with temporary-file recovery.
`replication_verify` loads both records in a separate local process, decodes
the caller-provided pinned public key, verifies the Ed25519 signature, compares
every frozen terminal/digest field, and exits non-zero on malformed, forged,
or mismatched evidence. This makes the local handoff executable and replayable
without granting the verifier authority to mutate the broker or workspace.

This remains local process evidence. It does not run the broker on another
host, provide cross-host custody, authenticate the operator or host, or
establish the phase-2 exit claim by itself. A real phase-2 exit still requires
a separate operator and host, reviewer-controlled signing-key custody, exact
digest-bound signed receipts, and independently retained recovery evidence.
