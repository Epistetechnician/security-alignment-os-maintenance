# Parallel implementation contract V1

State slice: `security-alignment-os-foundation-v1`.

User request 2026-09-07 authorizes end-to-end local implementation and reuse of eligible local/open-source code. Preserve provenance and licenses; do not import scientific artifacts, private data, credentials, or closed research results. External model execution, spend, settlement, deployment and scientific claims remain gated.

## Frozen seams

Rust 1.77. Existing Proposal, Decision, Kernel::admit(proposal, now), and Runtime::execute(kernel, proposal, decision, now) are the canonical interfaces. `contract::CapabilitySet` and `contract::Lifecycle` freeze the authority lattice and lifecycle transition vocabulary. New security checks may reject previously unsafe inputs. Kernel-owned consumption must happen immediately before runtime mutation. All local clocks are caller-supplied integer seconds; expiry is exclusive. Canonical digests are SHA-256 lowercase hex over canonical JSON. Evidence reviewer identities are local role assertions, not authenticated identities.

`receipts::CapabilityReceipt` is the local signed-receipt seam. Its Ed25519
signature binds exact proposal, decision, policy, capability, subject, and
validity fields; `ReceiptVerifier` adds a caller-owned trusted-key registry and
process-local replay set. `execution_gate::ExecutionGate` validates a typed
sandbox attestation and external job request but remains blocked for every
valid request in this slice. `schema::SchemaRegistry` binds each versioned
schema identity to one exact digest and rejects missing or mismatched records.

Evidence lane supplies `EvidenceRegistry::is_valid(evidence_id, now, subject_digest) -> bool` and `accept`/`revoke` transitions. `run_local_workflow` and `integration::run` accept an evidence reference before admission; raw claims alone never count as independently accepted evidence in the integrated workflow.

Runtime lane owns `src/lib.rs`, `src/specialist.rs`, `src/audit.rs`, `src/memory.rs`, and the adapter contracts. It provides reversible local dictionary execution, terminal freeze/kill, tenant-scoped consented retrieval, caller-owned durable memory, and immutable serving identities. No arbitrary process/network/model executor.

## Ownership and gates

- Kernel: src/lib.rs, src/contract.rs, src/receipts.rs, and
  src/execution_gate.rs; kernel tests and docs/kernel-v1.md.
- Evidence/evaluation: src/lib.rs, src/alignment.rs, src/benchmark.rs; docs/evidence-evaluation-v1.md.
- Runtime: src/lib.rs, src/specialist.rs, src/audit.rs; docs/runtime-v1.md.
- Coordinator: `src/integration.rs`, shared docs, Cargo/pnpm validation scripts and final review.

Each lane produces focused negative tests and a report naming touched slice, public interfaces, checks and residual gaps. Never change another lane files. No copied external implementation without license/revision/digest provenance. Local tests are local regression evidence, not independent scientific acceptance or OS enforcement.

## Task list

1. Freeze interfaces (this file).
2. Harden kernel and durable audit contracts.
3. Implement evidence provenance, artifact manifests, locks and adversarial evaluation contracts.
4. Implement local runtime lifecycle and specialist seam.
5. Integrate proposal/evidence/admission/execution/observation/rollback.
6. Test, independently review, inject deterministic failures, document exact limitations.
