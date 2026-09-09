# AWS Nitro Enclave fixed-operation runner v1

State slice: `security-alignment-os-foundation-v1`.

This runner is a machine-attested reproduction boundary for the fixed
`maintenance_process` operation. It is not independent human/operator
replication and must not be used to assemble a packet with a missing custody
attestation.

The enclave runs the existing 20-scenario `maintenance_replication_runner`.
After the report is durably read, it requests an AWS Nitro Secure Module
attestation document with the report digest as `user_data` and a fresh nonce.
The canonical envelope contains the report, its digest, the attestation
document, the attestation-document digest, and the claim ceiling. The envelope
is sent to the parent only over vsock port 5000; the enclave has no network
interface or credentials.

The parent must start a non-debug enclave from a signed EIF and preserve the
EIF metadata, PCR values, attestation document, raw envelope, request, source
revision, toolchain digest, evaluator digest, and separate evidence-custody
record. Debug-mode or console-attached output is not acceptable evidence.

The report’s Linux toolchain and evaluator digests are expected to differ from
the macOS Host-A digests. That difference is a reproducibility result, not a
reason to relax the packet contract. Packet assembly remains closed until the
frozen bundle and all required independent custody attestations match.
