# GCP Intel TDX machine-attested record V1

State slice: `security-alignment-os-foundation-v1`.

This record freezes one completed GCP Confidential Space execution of the
fixed maintenance operation. It is a `MachineAttestedReproduction`, not an
`IndependentReplication`.

## Bound execution

- Source revision: `c02e1f169df63646b9b97af2294c787243d2e070`
- Image reference:
  `us-west1-docker.pkg.dev/secops1219/maintenance-attested/maintenance-runner@sha256:2a93842ba24db580056d6852e12755d7ef2623b9b00adb6100a1e9091ba0fb45`
- TEE: `GCP_INTEL_TDX / CONFIDENTIAL_SPACE`
- Project and zone: `secops1219 / us-central1-c`
- Workload instance ID: `4179236304263605974`
- Report ID: `ada3819ee2af65da6587ac09f63c9ace7e0abf67d03df2fe4345989909c13872`
- Report digest: `1f9bddac4cb1282b17a665f4ee8fb80975a885adfad6427c802a1972f4bc9dbf`
- Scenarios: all 20 required scenarios

## Verification

The Google-signed attestation JWT verified against the published signer key.
The verification bound the nonce, issuer, audience, TDX model, Confidential
Space identity, Secure Boot, disabled debug, Intel TCB, immutable image
digest, source revision, instance identity, project, zone, and workload
service account. The canonical report digest, report identity, host and
operator signatures, scenario catalog, and containment/recovery relations also
verified.

The private evidence custody location is:

`gs://secops1219-maintenance-attested-20260909/gcp-c02e1f1-tdx-20260909/`

The dedicated instance was deleted after evidence capture. Raw logs and the
attestation token are not committed to this public repository.

## Claim boundary

This record does not establish a second independently administered host,
independent human operator, evaluator custody, evidence custody, AMD SEV
execution, or cross-cloud replication. A second provider with authenticated
out-of-band custody is required before the replication gate can become
anything other than `Inconclusive`.

The separate Gman H100 run remains a performance benchmark only. It is not
part of this TEE record and does not raise its claim ceiling.
