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

Packets use canonical JSON with temporary-file recovery. This is a local
handoff and comparison contract. It does not run the broker on another host,
provide cross-host custody, or establish the phase-2 exit claim by itself.
