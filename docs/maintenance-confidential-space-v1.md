# Google Confidential Space machine-attested runner V1

State slice: `security-alignment-os-foundation-v1`.

This binary is a future Google Confidential Space runner for the existing
fixed maintenance broker matrix. It has not been launched in Confidential
Space and this foundation slice does not authorize hosted execution. In an
authorized platform environment, it would request a Google Cloud Attestation
OIDC token with a fresh nonce, execute all 20 scenarios, and emit a canonical
envelope containing the token, token nonce, report digest, and signed local
report.

The result is `MachineAttestedReproduction`, not `IndependentReplication`.
Confidential Space authenticates measured workload properties and the VM
instance to a relying party; it does not create an independent human operator,
organization, evaluator custodian, or evidence custodian. The existing packet
contract also binds exact executable bytes, so a Linux evaluator cannot be
silently presented as Host A's macOS evaluator.

## Build and publish

The commands below are retained for a future authorized state slice only.
This foundation slice does not authorize networked image builds, registry
writes, or hosted execution. Do not run them.

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

Do not deploy or execute the current image. The runner places the raw OIDC
attestation token in its stdout envelope, and this repository does not
implement a protected output sink. The Dockerfile now sets
`tee.launch_policy.log_redirect=never`, which makes the Confidential Space
launcher reject stdout/stderr redirection metadata for this image. This policy
reduces one exposure path; it does not implement token custody or authorize a
launch. The runner now creates its report first and requests a token with a
nonce containing the report SHA-256 digest and a fresh 192-bit random
challenge. A relying party must verify the token signature and exact echoed
nonce, then confirm the nonce's report digest matches the envelope. The local
wrapper does not verify the token signature. Google requires relying parties
to compare requested and returned nonces. Google documents that workload
logging can forward stdout/stderr to
Cloud Logging or the serial console, and that attestation tokens can be used
by workload identity federation to access protected resources. Google also
recommends logging the minimum information and not logging sensitive
information. See [launch policies](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies),
[token handling](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources),
and [Confidential Space logging guidance](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/monitor-debug).

The output path is therefore not end-to-end safe yet. A separately authorized
state slice must provide a protected output channel and custody policy before
the workload can be launched. Keep the hosted execution gate closed until
then. If later authorized, verify the token issuer, audience, nonce,
`dbgstat=disabled-since-boot`, `swname=CONFIDENTIAL_SPACE`, stable support
attribute, VM self-link, and exact container image digest before accepting an
envelope. Missing or unverifiable output remains `Inconclusive`.

The local HTTP parser requires exact `Content-Length` framing when that header
is present, rejects duplicate or conflicting framing headers and unsupported
transfer encodings, and rejects JSON responses without a string `token` field.
These checks cover only synthetic local protocol responses; they do not
authenticate Google's signature or validate platform claims.

## Validation boundary

The current Host A macOS bundle cannot be assembled with the Linux report
because the packet requires equal evaluator and toolchain digests. A valid
machine-attested run therefore records a separate disposition until Host A is
also rerun in a compatible Linux environment and an independent custodian
authenticates both reports. Blockchain or transparency-log anchoring may bind
the final envelope digest and timestamp, but does not change this boundary.
