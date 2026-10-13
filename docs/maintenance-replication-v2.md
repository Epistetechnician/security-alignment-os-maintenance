# Maintenance replication report V2

State slices: `security-alignment-os-foundation-v1` and
`maintenance-replication-executable-identity-v2`.

V2 extends the local signed report and packet for the fixed maintenance
containment/recovery matrix. Each report includes the SHA-256 digest of the
maintenance broker executable. The runner hashes a regular executable before
the matrix, rechecks that digest immediately before each scenario launch, and
includes the digest in the host-signed report. Packet validation requires both
reports to bind the same broker bytes.

The runner still binds the frozen request and checkout manifest, source
revision label, Rust toolchain digest, evaluator executable and policy digests,
all required scenario results, and the existing claim ceiling. The claim
ceiling remains `local signed wire-consistency evidence for this fixed
maintenance operation only`.

## Compatibility

The verifier continues to validate signed V1 reports and packets exactly as
legacy records. V1 contains no maintenance broker executable digest and gains
no retroactive binary identity claim. New host runs emit V2 reports. The
baseline-manifest digest payload includes the report version byte; V1 and V2
records therefore retain their original version-specific digest values.

## Limits

The executable digest is an operator-runner observation, not a build-provenance
proof that the bytes came from the reported source revision. A same-UID actor
can still race the path-based digest read and OS process creation. Host labels,
operator labels, and signatures do not authenticate separate people, hosts, or
custody. The local rehearsal does not establish independent replication,
platform attestation, scientific validity, or production authorization.

Focused coverage checks broker replacement and symlink rejection, verifies
that the report binds the executable used by the real-process matrix, rejects
two reports with different broker digests, and keeps V1 packet verification
available. The full report remains `INCONCLUSIVE` for any claim requiring an
independent operator, host, or custodian.
