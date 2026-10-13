# AWS Nitro Enclave fixed-operation runner v1

State slices: `security-alignment-os-foundation-v1` and
`maintenance-platform-runner-hermetic-e2e-v1`.

This runner is a machine-attested reproduction boundary for the fixed
`maintenance_process` operation. It is not independent human/operator
replication and must not be used to assemble a packet with a missing custody
attestation.

The enclave runs the existing 20-scenario `maintenance_replication_runner`.
After the report is durably read, it requests an AWS Nitro Secure Module
attestation document with a digest binding the embedded implementation
revision, report digest, and image source-tree SHA-256 as `user_data`, plus a
fresh nonce. The report revision must equal the embedded image revision; the
envelope repeats both the revision and source digest for verifier inspection.
The canonical envelope contains the report, its digest, the attestation
document, the attestation-document digest, and the claim ceiling. The envelope
is sent to the parent only over vsock port 5000; the enclave has no network
interface or credentials.

The parent must start a non-debug enclave from a signed EIF and preserve the
EIF metadata, PCR values, attestation document, raw envelope, request, source
revision, toolchain digest, evaluator digest, and separate evidence-custody
record. Debug-mode or console-attached output is not acceptable evidence.

`pnpm run build:nitro-identity` derives the Git revision and a SHA-256 digest
over `Cargo.toml`, `Cargo.lock`, `build.rs`, `build_support`,
`infra/nitro-enclave`, and `src`. It fails when those inputs are modified,
missing, untracked, or ignored, and prints the two Docker build-argument values
as JSON. The command only prepares identity; it does not invoke Docker. The
Docker build receives both values;
`build.rs` recomputes the digest inside the build context and fails on a
mismatch. It embeds the identity at compile time.
The Dockerfile does not preserve either build argument as a runtime environment
variable, and the runner rejects attempts to supply runtime identity overrides.
The Nitro `user_data` digest binds the implementation revision, report digest,
and embedded source-tree digest. The local workload test checks that changing
the revision changes the expected attestation binding. This does not establish
that the Git revision is a trusted upstream identity or that an external
verifier has validated the Nitro quote.

`tests/nitro_enclave_image_policy.rs` covers wrong digests, dirty, untracked,
and ignored source inputs, revision/digest formats, runtime override rejection,
and binary/entrypoint wiring. These local checks do not build the image or EIF,
inspect AWS Nitro tooling, or validate enclave attestation. Hosted builds and
launches remain closed.

The report’s Linux toolchain and evaluator digests are expected to differ from
the macOS Host-A digests. That difference is a reproducibility result, not a
reason to relax the packet contract. Packet assembly remains closed until the
frozen bundle and all required independent custody attestations match.
