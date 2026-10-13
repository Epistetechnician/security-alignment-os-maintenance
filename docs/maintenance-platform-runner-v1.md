# Platform runner local integration

State slices: `security-alignment-os-foundation-v1` and
`maintenance-platform-runner-hermetic-e2e-v1`.

Both machine-attested runner binaries now route their production entry points
through a shared workload function that creates private temporary operation
state, invokes the configured maintenance replication runner, broker, and
evaluator, validates the canonical report, and assembles the platform envelope.
The Confidential Space adapter requests its token over the configured Unix
socket. The Nitro adapter supplies report digest and nonce to the NSM and sends
the envelope to the parent over vsock.

`tests/maintenance_platform_runners_e2e.rs` runs each workload function against
the actual local runner, broker, and evaluator binaries. It uses a local Unix
socket responder for the Confidential Space HTTP exchange and a synthetic
attestation callback for Nitro. The checks cover all 20 report scenarios,
canonical envelope output, report-digest binding, audience/nonce binding, and
the explicit machine-attested claim ceiling. The Nitro envelope's attestation
user data binds both the report digest and an embedded source-tree digest.

`tests/nitro_enclave_image_policy.rs` checks the source identity helper against
a clean temporary Git repository, rejects changed, untracked, ignored, and
mismatched source inputs, and checks the Dockerfile build, embedded identity,
runtime override rejection, binary install, and unprivileged entrypoint wiring.
This is a local build-contract check; it does not build the image or EIF.

This hermetic integration proves local process wiring and envelope construction
for these binaries. It does not call GCP Confidential Space, AWS Nitro NSM,
vsock, a cloud control plane, or a protected output sink; synthetic attestation
is not platform attestation. It does not establish independent operator or
evidence custody, Linux reproduction, scientific validity, or production
readiness.
