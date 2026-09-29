# Maintenance replication report V3

State slices: `security-alignment-os-foundation-v1` and
`maintenance-replication-runner-identity-v3`.

V3 adds `replication_runner_executable_digest` to each signed host report. The
runner hashes the current process executable before starting the 20-scenario
matrix, checks it again after the matrix, and signs the observed digest into
the report identity and signatures. The packet identity binds each signed
report ID, so the per-host runner digest is covered by the packet. Different
hosts may report different runner digests.

V3 retains V2's maintenance broker executable binding and the evaluator,
request, checkout manifest, toolchain, policy, and scenario bindings. The
baseline-manifest digest payload keeps its report-version byte, so V1 and V2
packets are checked against their original version-specific values. V1 and V2
reports remain verifiable with their original serialized identities: V1 has
no broker or runner digest; V2 has a broker digest and no runner digest.

## Limits

The runner digest is a signed local observation. It does not prove that the
binary was built from the reported source revision, and it does not authenticate
the host, operator, or evidence custodian. A reviewer would need the exact
executable bytes or a trusted image/build manifest to independently compare the
reported digest. The executable path is read before and after the matrix; a
hostile same-UID actor may still race filesystem changes around those reads.
The report claim ceiling remains `local signed wire-consistency evidence for
this fixed maintenance operation only`.

Focused coverage checks V1 and V2 compatibility, V3 digest signature binding,
tampering and missing-field rejection, distinct per-host runner identities,
and the real-process runner's digest observation. These checks establish only
local contract behavior. They do not establish independent reproduction,
platform attestation, scientific validity, or production authorization.
