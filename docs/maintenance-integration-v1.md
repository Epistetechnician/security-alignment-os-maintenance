# Repository maintenance integration V1

State slice: `security-alignment-os-foundation-v1`.

## Current local implementation status

Audit date: 2026-09-23. State slice: `security-alignment-os-foundation-v1`.

The original maintenance workflow contract was developed from `fe4195b`. The
current checkout adds a fixed-operation process boundary and a local
20-scenario replication runner. `tests/maintenance_process_e2e.rs` exercises
real broker/evaluator subprocesses, mutation, replay rejection, cancellation,
rollback, and crash recovery. `tests/maintenance_replication_runner.rs`
executes and signs the fixed scenario matrix using local fixtures. These checks
establish local process and packet behavior only.

The separate-host packet remains `valid_local_packet` / `Inconclusive` until an
independent host, operator, and evidence custodian reproduce and authenticate
the exact frozen run. The hosted Confidential Space and Nitro wrappers are
environment-specific; hermetic local tests execute their workload functions
against actual local runner, broker, and evaluator binaries with synthetic
protocol and attestation adapters, not platform attestation. The local Nitro
image-policy tests reject dirty or mismatched source identity, verify build-time
digest checking and compile-time embedding, and reject runtime overrides,
without building an image. The GCP wrapper places its OIDC
attestation token in stdout. Its image now sets the Confidential Space
`log_redirect=never` launch policy, but the repository still has no protected
output sink or token-custody workflow. Do not launch it. Protected output
custody and any hosted execution remain outside this state slice.

The capability broker and maintenance process are separate boundaries. The
enforcement lane owns `broker.rs`, supervisor binaries, sandbox policy,
durable execution records, cancellation, and recovery. The fixed maintenance
process owns one Markdown whitespace transformation, its separate evaluator,
request binding, and workflow tests. Neither is a generic patch executor.

## Existing interface and remaining general-operation gap

The current broker accepts `FileTransformRequest` through `BrokerRequest::Execute`
and returns `BrokerResponse`. It binds source and executable digests, relative
paths, byte and runtime limits, nonce, and expiry. Its only operation is
`UppercaseAscii`, writing a previously absent destination. It is not a general
patch executor. `BrokerResponse::Completed` carries a capability receipt and
output digest; quarantine and frozen responses represent failure.

Generic maintenance integration needs an explicit request binding the checkout
baseline, complete patch, frozen evaluation packet, and exact target paths.
The broker must verify that binding before granting a lease. Cancellation and
rollback need transaction-bound requests and terminal result receipts; the
present Hello/Execute interface has neither. A workflow test executor cannot
substitute for those enforcement operations.

The implemented [maintenance process boundary](maintenance-process-v1.md)
preserves the existing broker protocol and exercises signed evaluation and
durable mutation for a single Markdown whitespace task. Its private-checkout
trust boundary is explicit; it does not inherit the existing supervisor's
sandbox or implement a generic patch lease.

## Local integration coverage and remaining gate

The local implementation binds the exact request bytes, checkout baseline,
evaluator executable, fixed input/tests, and policy digests before mutation.
It rechecks the evaluator's pinned digest immediately before spawning it, then
rejects stale or mismatched inputs, checks the committed bytes, and restores or
freezes on failed recovery. The real-process tests cover evaluator replacement
after broker startup, path escapes, symlinks and hardlinks, changed evaluator
requirements, cancellation, lease expiry, replay, interrupted commits, and
concurrent writer fencing. This closes the fixed local operation gate; it does
not establish generic repository maintenance, inherited sandbox enforcement,
authenticated identity, or independent replication.

## Subsequent gates

1. Independent replication: use the [V2 report contract](maintenance-replication-v2.md)
   to bind the exact maintenance broker executable as well as the frozen
   containment/recovery packet. The legacy [V1 contract](maintenance-replication-v1.md)
   remains verifiable without broker executable binding. Actual separate-host
   reproduction remains open.
2. Shadow adaptation: candidate updates compete against an immutable baseline
   on locked evaluations; independent authority controls promotion and rollback.
3. Causal research: separately accepted preregistration, custody, identity, and
   spend gates precede interventions and held-out monitor evaluation.
4. External market: outsource the fixed job class only after independent receipt
   verification; escrow and settlement require their own authorization.

These produce distinct evidence for containment, bounded usefulness, replication,
controlled adaptation, causal effects, and outsourced computation. No individual
gate establishes general alignment. Model execution remains separately gated.
