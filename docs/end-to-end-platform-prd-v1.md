# Proof-Carrying, Capability-Bounded Agent Platform — End-to-End PRD V1

State slice: `security-alignment-os-foundation-v1`.

Status: proposed implementation contract. This PRD turns the platform thesis
into a sequence of bounded releases. It is a product and engineering plan; it
does not authorize model execution, provider calls, spend, settlement,
training, scientific assessment, or production traffic.

## Problem Statement

An agent can produce a useful maintenance change, but an ungoverned agent can
also request excess authority, substitute evidence, exfiltrate data, alter its
evaluator, replay an old capability, or leave a partial mutation behind. A
market, a cryptographic receipt, a sandbox, or a model report solves only one
part of that problem. None proves that inputs are truthful, the work is useful,
the agent is aligned, or the result benefits a person.

The repository currently contains local Rust contracts for proposals,
admission, capabilities, evidence, provenance, replay, rollback, monitoring,
fixed jobs, and a process broker. Those contracts are valuable regression
infrastructure, but several boundaries remain caller-owned: authenticated
identity, independent review, hostile-host isolation, cross-process
linearizability, external custody, model execution, and payment settlement.

The product needs one narrow path that can complete useful work under enforced
limits and produce a reviewable receipt, followed by independent replication,
controlled adaptation, causal alignment research, and only then outsourced
execution. Each stage must earn its own claim and preserve explicit nonclaims.

## Solution

Build a Rust-native control plane and a set of separately reviewed adapters:

```text
intent
  -> typed proposal
  -> frozen adversarial evaluation
  -> independent evidence validation
  -> deterministic admission
  -> short-lived capability lease
  -> isolated reversible execution
  -> continuous observation
  -> completion, rollback, quarantine, freeze, or shutdown
```

The first product is a repository-maintenance agent. It proposes one bounded
patch, receives a temporary lease to an isolated checkout, invokes a separate
evaluator against frozen requirements, and applies the patch only after a
receipt binds the exact patch, executable, inputs, tests, policy, baseline, and
lease. Every failed or ambiguous transition fails closed. The model remains a
proposal source and never controls authority, evidence acceptance, policy,
review, evaluator configuration, payment, or promotion.

Later releases reuse the same typed seams:

1. A second operator reproduces containment and recovery on a separate host.
2. Candidate updates compete with an immutable baseline in shadow mode.
3. Preregistered causal monitors are tested against held-out behavioral effects.
4. A fixed, already-specified job class is outsourced and settled only after
   independent receipt verification.

The intended market claim is narrow: collateral, escrow, price discovery, or
payment can support externally executed jobs whose typed receipts satisfy a
frozen acceptance policy. A market price is an advisory signal until a later
empirical and governance gate.

## Goals

- Make every authority transition explicit, typed, digest-bound, and reversible.
- Complete one useful maintenance task under a real process boundary.
- Ensure missing, stale, contradictory, substituted, or expired evidence cannot
  release authority.
- Make crash recovery deterministic and conservative.
- Separate proposing, evaluating, validating, reviewing, operating, and
  releasing roles.
- Preserve immutable production bases and independently controlled promotion.
- Produce reproducible aggregate claim packets with clear ceilings.
- Keep all implementation in Rust under the foundation state slice.

## Non-goals

- General autonomous agents or arbitrary shell, code, network, or wallet access.
- A claim of general alignment, consciousness, introspection, or human benefit.
- Treating ZK, FHE, MPC, attestation, or market prices as universal safety
  proofs.
- Live model training, provider execution, financial value movement, or public
  production deployment in the foundation release.

## Actors

- **Requester:** defines the bounded objective, inputs, output schema, deadline,
  budget, and acceptance policy.
- **Proposer:** produces a typed candidate or patch and no authority decision.
- **Evaluator:** independently executes frozen checks and emits a signed result.
- **Validator:** recomputes evidence and receipt equations from exact bytes.
- **Reviewer:** accepts or rejects a packet; must be distinct from proposer and
  evaluator, with identity authentication supplied by a later adapter.
- **Operator:** owns checkout, key, policy, runtime, and kill-path custody.
- **Supervisor:** enforces the process boundary, lease, resource limits, and
  rollback behavior outside the model process.
- **Replication operator:** reproduces a frozen packet on another host.
- **Adaptation authority:** controls shadow, canary, promotion, and rollback.
- **Market participant:** bids, quotes, or forecasts; cannot accept evidence or
  release payment.
- **Auditor:** reads immutable aggregate records and claim boundaries.

## User Stories

1. As a requester, I want to describe one measurable maintenance objective, so
   that the evaluator can decide success without interpreting agent intent.
2. As a requester, I want to freeze the target path, baseline digest, output
   schema, deadline, resource budget, and acceptance policy, so that the agent
   cannot change the rules after proposing work.
3. As a proposer, I want to submit exact before and after bytes, so that my
   useful change can be reviewed without granting me filesystem authority.
4. As a proposer, I want invalid proposals rejected without mutation, so that
   a malformed request cannot damage the checkout.
5. As an evaluator, I want the exact proposal and frozen test manifest, so that
   my result cannot silently apply to a different patch.
6. As an evaluator, I want to run in a separate process with bounded input,
   output, and time, so that evaluator failure cannot become broker authority.
7. As a validator, I want to recompute every digest and signature, so that an
   unsigned or substituted result is quarantined.
8. As a reviewer, I want a complete packet containing patch, executable, input,
   test, policy, custody, and lease digests, so that acceptance has a precise
   subject.
9. As an operator, I want the broker to own the evaluator path and public key,
   so that the proposer cannot select a permissive evaluator or key.
10. As an operator, I want temporary authority to expire during execution, so
    that a long-running process cannot outlive its lease.
11. As an operator, I want cancellation outside the model process, so that a
    kill decision remains available when the model is uncooperative.
12. As an operator, I want a private isolated checkout, so that only the named
    target can be changed.
13. As an operator, I want a durable intent recorded before the first write, so
    that a crash has enough information to restore the baseline.
14. As an operator, I want interrupted work restored and frozen, so that the
    broker never resumes an ambiguous transaction.
15. As an operator, I want replayed nonces and receipts rejected across
    restarts, so that consumed authority cannot be reused.
16. As an operator, I want concurrent writers blocked, so that two decisions
    cannot race on one checkout or journal.
17. As a reviewer, I want unchanged neighbor files verified, so that a successful
    target update cannot hide collateral mutation.
18. As an auditor, I want raw payloads excluded from aggregate records, so that
    auditability does not require retaining sensitive content.
19. As an auditor, I want every claim to state its ceiling and nonclaims, so
    that local tests are not presented as deployment or alignment evidence.
20. As a replication operator, I want a frozen packet and exact toolchain
    digests, so that another host can reproduce the same test.
21. As a replication operator, I want the original operator unable to rewrite
    my result, so that replication is genuinely independent.
22. As an adaptation authority, I want the production base immutable, so that a
    candidate cannot alter its own comparison target.
23. As an adaptation authority, I want candidate updates shadowed before
    canarying, so that regressions are observed without production authority.
24. As an adaptation authority, I want independent promotion and rollback, so
    that the candidate cannot approve its own update.
25. As an evaluator, I want locked fit, tune, and assessment partitions, so that
    thresholds cannot be optimized on held-out results.
26. As an alignment researcher, I want causal interventions rather than probe
    correlations, so that monitor predictions are tested against behavior.
27. As an alignment researcher, I want held-out tasks and adversarial evaluator
    gaming tests, so that a monitor must generalize beyond its training cases.
28. As a privacy operator, I want explicit custody roots and deletion deadlines,
    so that raw traces do not persist beyond the approved retention window.
29. As a buyer, I want a fixed job specification and acceptance policy, so that
    provider bids are comparable.
30. As a provider, I want a bounded capability lease and clear payout rule, so
    that accepted work has predictable obligations.
31. As a market participant, I want prices tied to one immutable job identity,
    so that a quote cannot migrate to a changed objective.
32. As a market participant, I want price data labeled advisory until calibrated,
    so that a thin or manipulated market is not treated as probability truth.
33. As a settlement authority, I want payment release to require accepted
    evidence, so that a provider cannot be paid for an unverifiable result.
34. As a settlement authority, I want one durable idempotency key across payment
    rails, so that a job cannot pay twice.
35. As a governance operator, I want each release to name its evidence and
    reviewer, so that authority is auditable and reversible.
36. As an incident responder, I want a kill path independent of the model and
    supervisor child, so that unsafe execution can be terminated.
37. As a maintainer, I want all state transitions represented by Rust types, so
    that invalid states are difficult to construct.
38. As a maintainer, I want implementation-diverse checkers, so that one
    validator's bug does not define the only acceptance path.
39. As a security reviewer, I want hostile same-UID and compromised-host
    assumptions explicit, so that private permissions are not confused with
    strong isolation.
40. As a release authority, I want unresolved blockers to stop promotion, so
    that uncertainty produces quarantine or freeze rather than optimism.

## Lifecycle and claim ladder

The canonical lifecycle is:

```text
Proposal
  -> Evaluated
  -> EvidenceValidated
  -> Admitted
  -> Leased
  -> Executing
  -> Completed
       |-> RolledBack
       |-> Quarantined
       |-> Frozen
       `-> Shutdown
```

There is no direct proposal-to-execution edge. Rejection and quarantine leave
governed state unchanged. A lease cannot outlive the proposal, evidence, policy,
or execution deadline. A consumed lease cannot be recreated after a crash.

Evidence claims are ordered as `Local < Attested < Proven < External`, but the
label alone never raises evidence quality. The first maintenance release earns
only `LocalBoundedMaintenanceExecution`. Separate-host reproduction may earn
`ReplicatedBoundedMaintenanceExecution`. Shadow adaptation, causal research,
and outsourced computation each have separate ceilings. None earns a general
alignment claim.

## Implementation Decisions

### 1. Shared Rust contract

Create versioned canonical records for proposal, capability, lease, evaluator
job, evaluator receipt, evidence packet, checkout baseline, observation,
cancellation, rollback, terminal outcome, and claim envelope. Every record has
a state-slice identifier, exact digest bindings, exclusive expiry semantics,
and bounded field sizes. Canonical JSON is the initial interchange format;
binary encoding is a later optimization only if canonical equivalence is proven.

### 2. Security kernel

Keep authority as an explicit powerset over read, write, network, secrets,
spend, replication, code execution, and self-modification. No capability implies
another. Admission is pure and fail closed. Capability consumption occurs once,
immediately before mutation. Replay, policy drift, budget overflow, stale clocks,
and model-requested authority reject or quarantine without mutation.

### 3. Evidence plane

Separate evidence production, validation, review, and admission. Bind exact
source, executable, input, test, policy, configuration, custody, and result
digests. Record provenance, license, version, retention, validator, reviewer,
contradiction, and claim ceiling. Preserve aggregate-only release packets and
keep raw payloads below explicit owner-controlled custody roots.

### 4. Maintenance execution wedge

Use one fixed operation first: remove trailing ASCII spaces from one root-level
Markdown file in an operator-provisioned private checkout. The evaluator
recomputes the transformation from bytes; it does not accept proposer-supplied
booleans or execute proposer commands. The broker owns evaluator configuration,
key custody, checkout scope, cancellation, timeout, lock, durable intent,
atomic replacement, postcheck, rollback, and freeze.

The first implementation must refuse symlinks, hardlinks, special files,
ambiguous paths, oversized manifests, stale baselines, changed evaluator
identity, duplicate nonces, and occupied state locks. Same-UID hostile processes
and compromised hosts remain outside this boundary until a separately reviewed
OS or hardware adapter is available.

### 5. Process and recovery model

The supervisor receives only canonical fixed-operation input with a cleared
environment. The broker checks cancellation and expiry before evaluation, after
evaluation, immediately before replacement, and after replacement. It persists
an intent and baseline backup before writing. Recovery never resumes; it restores
an unambiguous baseline and freezes. An ambiguous or failed restoration remains
frozen. State is bound to the original checkout and policy configuration.

### 6. Independent replication

Export a frozen replication packet containing source and toolchain digests,
configuration, test manifest, expected outcomes, host prerequisites, retention
rules, and claim ceiling. A second operator on a separate host runs the packet,
retains only aggregate results, signs its own result through an independently
managed identity, and cannot modify the original packet. Replication is a
release gate, not a background confidence score.

### 7. Shadow adaptation

Represent the immutable base, candidate identity, training-data manifest,
resource accounting, evaluation lock, canary policy, promotion authority,
rollback target, and freeze state as separate records. Candidate generation may
be proposed by a model or trainer, but evaluation, promotion, and rollback are
independent. Production traffic remains on the immutable base until shadow and
canary gates pass.

### 8. Causal alignment research

Treat behavioral, mechanistic, and scalable-oversight tracks as distinct. Freeze
model/runtime/asset/corpus/split/wrapper/feature/estimand/control/power/
multiplicity/repeat/attrition/prediction-lock/custody/validator identities
before execution. Use interventions and held-out causal scrubbing. A monitor
must predict consequential behavioral changes across held-out tasks and survive
evaluator-gaming probes. Model execution requires a fresh packet, exact identity,
positive hard spend ceiling where applicable, and independent signed acceptance.

### 9. External execution market

Start with one fixed job class whose program, inputs, output schema, acceptance
policy, resource budget, deadline, privacy rule, and claim ceiling are already
frozen. Providers bid against the same job digest. Independent validation
resolves `YES` or `NO`; only the control plane emits a payout authorization.
Market prices begin advisory. Hyperliquid, payment rails, ZK, FHE, and MPC are
adapters with separate threat, liveness, collusion, privacy, and settlement
assumptions. No chain or payment event proves computation correctness by itself.

### 10. Governance and release

Every release has a machine-readable manifest, human claim-boundary report,
test results, unresolved blockers, reviewer identity, and rollback target.
Release authority is capability-bounded and external to the model. Freeze is
terminal for the affected identity. Closed research slices cannot be reopened
or retuned under their old identity.

## Delivery phases and exit gates

### Phase 0 — contract freeze

Deliver the threat model, authority lattice, state machine, claim ladder,
failure budgets, schema registry, protected-surface list, and source/provenance
manifest. Exit only when every authority transition has an actor, predecessor,
successor, evidence requirement, failure disposition, and nonclaim.

### Phase 1 — maintenance process

Integrate the fixed broker/evaluator with the canonical kernel and evidence
plane. Demonstrate one useful patch, untouched neighbors, exact output, signed
receipt, lease expiry, cancellation, stale baseline, evaluator substitution,
path escape, replay, concurrent-writer rejection, crash recovery, and freeze.

Exit claim: local bounded maintenance execution on the tested host and fixed
operation. No independent or production claim.

### Phase 2 — independent replication

Run the same frozen packet under a separate operator and host. Compare exact
terminal outcomes, rollback bytes, untouched-file digests, receipt bindings,
and recovery disposition. Any mismatch closes the candidate and preserves the
failure packet without retuning.

Exit claim: replicated bounded containment and recovery for the declared host
set. Hostile same-UID and compromised-host guarantees remain excluded.

### Phase 3 — shadow adaptation

Add immutable-base comparison, locked evaluation streams, candidate resource
accounting, shadow telemetry, canary policy, independent promotion, automatic
rollback, and terminal freeze. No candidate can alter its evaluator, policy,
baseline, or release authority.

Exit claim: controlled adaptation under the declared evaluation and rollback
conditions. This is not evidence of alignment or generalization.

### Phase 4 — causal alignment research

Prepare a fresh preregistered protocol and independent acceptance packet. Run
qualification first, lock predictions before assessment effects, retain raw data
only under approved custody, validate aggregates independently, and perform
held-out causal scrubbing. A failed gate closes the protocol identity.

Exit claim: only the exact local or held-out causal qualification supported by
the accepted packet. No introspection, consciousness, or general alignment
claim follows automatically.

### Phase 5 — external execution market

Publish the already-specified job class, accept provider offers, execute through
an authorized adapter, verify receipts independently, resolve the outcome, and
settle through one separately authorized payment rail. Introduce testnet or
zero-value simulation before any real value. Reconcile every external event and
freeze on ambiguity.

The current foundation slice implements only the zero-value local portion of
this phase: a verified fixed-job proposal can become a digest-bound
`crypto_adapters::SettlementIntent` only after accepted evidence and artifact
registry checks, pass through one of three provider-shaped unsigned dry-run
wire labels, resolve into an authorization-required settlement record, and
produce a deterministic zero-value payout proposal through a canonical
append-only journal with an independent checker. Missing evidence is not
inferred, ambiguous observations quarantine, and a matching observation never
authorizes payout. Live chain reads, signing, provider execution, independent
settlement authority, disputes, and real value remain later gates.

Exit claim: verifiable outsourced execution and settlement for the fixed job
class, subject to the declared provider, chain, payment, and dispute limits.

## Testing Decisions

Tests validate observable contracts and failure dispositions, not private
implementation structure. Every rejection test asserts both the terminal reason
and preservation of all governed bytes, counters, journal tips, and authority.

- Kernel unit and property tests cover lattice non-implication, lifecycle
  transitions, expiry, budgets, replay, receipt equations, and no-mutation-on-
  rejection.
- Evidence tests cover exact subject binding, stale or contradictory records,
  reviewer-role collisions, retention, revocation, canonical persistence, and
  aggregate packet redaction.
- Maintenance process tests use real broker, evaluator, and supervisor
  processes. They cover useful completion, unchanged neighbors, malformed and
  substituted evidence, executable/key/test-policy drift, path/link escape,
  expiry, cancellation before and after replacement, timeout, replay across
  restart, concurrent writers, interrupted intent, failed rollback, and
  redirected recovery.
- Adversarial benchmark tests use clean-room semantic families for prompt
  injection, tool misuse, exfiltration, privilege escalation, deceptive
  compliance, reward hacking, provenance tampering, Sybil behavior, economic
  manipulation, and unsafe self-modification. Fit, tune, and assessment are
  document-disjoint and prediction-locked.
- Replication tests compare machine-readable packets across hosts and verify
  that the second operator cannot alter the original identity or result.
- Adaptation tests replay identical streams, enforce immutable bases, compare
  shadow and canary outputs, and inject promotion, rollback, resource, and
  evaluator failures.
- Causal tests verify intervention reach, no-op identity, repeatability,
  controls, held-out prediction locks, uncertainty, multiplicity, attrition,
  retention deletion, and independent aggregate validation.
- Market tests verify immutable job identity, offer eligibility, price bounds,
  observation replay, resolution, timeout, dispute, idempotent payout intent,
  chain/payment reconciliation, and no settlement on unverified evidence.

Required commands remain `pnpm run lint:fast`, `pnpm run test:focused`,
`pnpm run verify:contracts`, and the full `pnpm run lint` gate. No test result
is called independent acceptance unless a genuinely separate validator and
operator perform that role.

## Out of Scope

- Arbitrary agent shell execution, unrestricted repository diffs, unrestricted
  network or secret access, self-replication, self-modification, and wallet
  control.
- Model downloads, training, provider calls, paid compute, external corpus
  acquisition, and raw scientific trace retention without a fresh authorized
  packet.
- Hyperliquid mainnet, real-money prediction markets, Stripe or Tempo production
  payouts, and legal or regulatory conclusions.
- Treating Boundless, HEIR, Arcium, ZK, FHE, MPC, attestation, or an open-source
  runtime as a drop-in guarantee. Each requires its own adapter, version,
  provenance, threat model, and independent acceptance.
- General alignment, human-benefit, consciousness, introspection, benchmark,
  frontier-capability, or production-readiness claims.
- Reopening closed Astral or Oak Lab identities, reusing their scientific
  artifacts, or promoting a local contract into the accepted Evidence Ledger.

## Further Notes

The highest-return engineering order is to finish and independently review the
fixed maintenance process, then replicate it. Adding markets or model
adaptation before that gate would expand the trust surface without increasing
the strongest claim. The maintenance wedge should remain useful enough to
exercise real commit and recovery paths, but narrow enough that every byte and
authority transition can be inspected.

The process boundary is stronger than the pure-data contract but still bounded:
owner-only permissions are not hostile same-UID isolation, a signed evaluator
receipt authenticates bytes under a configured key but does not prove evaluator
independence, and a successful rollback test is not a formal proof of all crash
interleavings. These limits belong in every release packet.

The product is successful when it can show useful work completed under enforced
limits, reproducibly recover from failures, and stop at each claim boundary.
The platform must prefer quarantine or freeze whenever evidence, identity,
timing, custody, or recovery is uncertain.
