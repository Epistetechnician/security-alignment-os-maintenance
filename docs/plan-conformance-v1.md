# 841 plan conformance V1

State slice: `security-alignment-os-foundation-v1`.

This record prevents the local implementation from being described as a
production-ready platform. The current commit implements the contract and
local pure-data portions of the plan. It does not open provider, model,
financial, deployment, or scientific gates.

| PRD phase | Current implementation | Exit status |
| --- | --- | --- |
| 0. Contract | `contract`, `schema`, threat model, claim ceiling, explicit lifecycle transitions, authority lattice, failure budgets, and exhaustive digest-only property reports | Partial; formal review and machine-checked proof remain open |
| 1. Maintenance process | `Kernel` with validated policy, single-use capabilities, nonce-bound single-use replay journal, quotas, canonical journal, persisted lifecycle state machine, failure-budget freeze wiring, atomic replacement/recovery, runtime rollback/freeze/kill and snapshots, local checker, fault scenarios, Ed25519 capability receipts, receipt-gated coordinator execution, typed execution gate, and the separate Rust capability broker with durable admitted/executing/commit/rollback journal for the fixed Markdown trailing-space operation | Advanced local slice; formal model checking, authenticated host identity, Linux hardening, and production deployment remain open |
| 2. Independent replication | `replication::FrozenReplicationPacket`, signed second-operator result, exact result comparison, mismatch quarantine, and canonical packet recovery | Contract implemented; no separate host, authenticated operator, or independent acceptance evidence is claimed |
| 3. Shadow adaptation | `adaptation::AdaptationRecord` freezes base, candidate, evaluator, policy, resource, prediction-lock, canary, promotion, rollback, and terminal state bindings | Local pure-data contract; no training, serving, canary traffic, deployment, or production authority |
| 4. Causal alignment research | `causal::CausalProtocol` freezes track identities and enforces qualification, prediction-lock, held-out, custody, retention, and independent-acceptance ordering | Preregistration contract only; no model execution or causal/behavioral evidence |
| 5. External execution market | `market::SumJob` and local receipt verifier bind one fixed job class, exact offers, result recomputation, and authorization-required settlement; `crypto_adapters` adds registry-backed zero-value eligibility, provider-shaped canonical wire envelopes with duplicate-key rejection, unsigned dry-run preparation, exact observation reconciliation, append-only replay, idempotency, quarantine, canonical recovery, and an independent journal checker; `execution_gate::ExecutionGate` blocks external execution | Local simulation and offline adapter contracts only; no provider, payment, chain, wallet, signing, or value movement |
| Shared evidence and governance | `EvidenceRegistry`, `artifacts::ArtifactManifest`, `custody::CustodyRegistry`, meet-only `claims::ClaimEnvelope`, benchmark fixtures, `alignment::PredictionLock`, existing `governance::ReleaseRegistry`, audit records, canonical persistence, and exact subject/provenance binding | Local caller-owned evidence only; authenticated identities, custody enforcement, held-out evidence, recurring review, and public release remain open |

## Narrow compute bridge

`market::SumJob` is the first wedge described by the pasted thesis: one fixed
program identity, committed input digest, output schema, ordinary receipt type,
privacy requirement, deadline, price ceiling, recomputed output, exact-job typed
offers, immutable identity revalidation, and an authorization-required typed
settlement proposal. `crypto_adapters` now carries that proposal through
registry-backed zero-value eligibility, provider-shaped canonical dry-run
wire, and an independently checked local replay journal. It does not authorize
or simulate a real payment.
It is intentionally local. No
Hyperliquid, Boundless, HEIR, Arcium, ZK proof, FHE/MPC runtime, provider bid,
wallet, signing key, network call, or settlement transaction is integrated.

## Parallel structure

The code is now split into Rust module seams corresponding to the plan's
workstreams: kernel/contract/receipts, evidence/artifacts, benchmark/faults,
alignment, and runtime/adapters/execution-gate. The current checkout does not
claim that those seams are independent production services or independent
scientific validators. The coordinator gate is the Cargo test, Clippy, format,
and digest review over the combined local tree.

The first product-wedge routing seam is also local Rust: `routing::RoutingRequest`
and `routing::RoutingDecision` bind a caller-selected specialist to an active
tenant consent grant, immutable identity digest, input digest, and expiry. It
does not classify raw prompts, load a model, or invoke a specialist.

## Claim ceiling

Passing local checks establish only local Rust contract and caller-owned
persistence evidence. They do not establish agent alignment, general safety,
cryptographic proof of input truth, provider correctness, production security,
or human-benefit outcomes.
