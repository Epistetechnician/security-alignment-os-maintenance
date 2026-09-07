# Research roadmap

State slice: `security-alignment-os-foundation-v1`.

## Gate 1 — Security kernel

Replace the local reference runtime with a separately reviewed capability
broker, OS sandbox, network egress policy, secret broker, append-only durable
journal, staged rollback, and independent kill path. Formally verify the
non-escalation and no-mutation-on-rejection invariants.

## Gate 2 — Agent security benchmark

Add Semantic IR families for prompt injection, tool abuse, exfiltration,
memory tampering, self-replication, reward hacking, deceptive compliance,
economic manipulation, and unsafe self-modification. Use fresh held-out attack
families and independent runners. Passing tests remain bounded evidence.

## Gate 3 — Causal alignment measurement

Use the current research boundary only through a fresh, independently accepted
protocol. For the authorized Gemma 3 bundle line, bind exact source/runtime/model/
asset/corpus/custody/provider identities, run qualification before effects,
lock fit/tune predictions, perform held-out causal scrubbing, delete raw traces
within the declared retention window, and validate aggregates independently.
No failed prior protocol may be retuned or reused as scientific input.

## Gate 4 — Safe adaptation

Any successor to the closed Oak Lab protocols must use a new identity, a fully
executable state/update/resource contract, independent review before
implementation, shadow-mode updates, immutable production base, canary release,
and automatic rollback. The model may propose an update; it may not approve or
deploy its own update.

## Gate 5 — Deployment

Require external red-team replication, supply-chain review, attested runtime
identity where available, incident exercises, capability-by-capability release
gates, and reproducible public claim packets. Production authority remains
closed until those gates are independently satisfied.

## Local implementation status after parallel build

The local kernel, canonical journal persistence/recovery, explicit capability
lattice, failure budgets, versioned schema registry, exhaustive property checks,
signed capability receipts, typed execution gate, artifact-manifest lifecycle,
custody records, meet-only claim envelopes, evidence
lifecycle, measurement locks, dictionary rollback, specialist
consent/retrieval, ordinary fixed-job receipts, release-state contracts,
independent local checks, and fault-injection scenarios are implemented.
External enforcement, authenticated custody, scientific assessment, training
and deployment remain the gates above.
Public fixture split names are organizational labels, not independent held-out
data. See [plan-conformance-v1.md](plan-conformance-v1.md) for phase-by-phase
status and [integration-v1.md](integration-v1.md) for the exact boundaries.
