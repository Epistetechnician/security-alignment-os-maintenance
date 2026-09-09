# Google Confidential Space machine-attested runner V1

State slice: `security-alignment-os-foundation-v1`.

This deployment runs the existing fixed maintenance broker matrix in a
production Google Confidential Space workload. The workload requests a Google
Cloud Attestation OIDC token with a fresh nonce, executes all 20 scenarios, and
emits a canonical envelope containing the token, token nonce, report digest,
and signed local report.

The result is `MachineAttestedReproduction`, not `IndependentReplication`.
Confidential Space authenticates measured workload properties and the VM
instance to a relying party; it does not create an independent human operator,
organization, evaluator custodian, or evidence custodian. The existing packet
contract also binds exact executable bytes, so a Linux evaluator cannot be
silently presented as Host A's macOS evaluator.

## Build and publish

Build from the exact source revision being evaluated. The image digest, source
revision, toolchain record, evaluator digest, request digest, baseline manifest
digest, and report digest must be retained together. Do not use `:latest` as
evidence.

```text
docker build -f infra/confidential-space/Dockerfile -t \
  us-docker.pkg.dev/PROJECT_ID/maintenance-attested/maintenance-runner:REVISION .
docker push \
  us-docker.pkg.dev/PROJECT_ID/maintenance-attested/maintenance-runner:REVISION
```

Deploy the immutable image reference to a production Confidential Space image,
use `SEV` or `TDX` as supported by the selected zone, attach only the workload
service account, enable Shielded Secure Boot, and set
`tee-container-log-redirect=cloud_logging` if the envelope is being recovered
from Cloud Logging. The production image root is read-only, so the workload's
ephemeral checkout, keys, and reports are written under `/tmp`, while the
attestation socket remains under `/run`. Verify the attestation token
issuer, audience, nonce, `dbgstat=disabled-since-boot`,
`swname=CONFIDENTIAL_SPACE`, stable support attribute, VM self-link, and exact
container image digest before accepting the envelope.

The workload emits no raw scenario logs. Cloud Logging or a separately
protected output bucket must be treated as evidence custody, and missing or
unverifiable output remains `Inconclusive`.

## Validation boundary

The current Host A macOS bundle cannot be assembled with the Linux report
because the packet requires equal evaluator and toolchain digests. A valid
machine-attested run therefore records a separate disposition until Host A is
also rerun in a compatible Linux environment and an independent custodian
authenticates both reports. Blockchain or transparency-log anchoring may bind
the final envelope digest and timestamp, but does not change this boundary.
