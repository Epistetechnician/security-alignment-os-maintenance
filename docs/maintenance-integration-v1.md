# Repository maintenance integration V1

State slice: `security-alignment-os-foundation-v1`.

The maintenance lane is isolated on `maintenance-workflow-v1`, based on
`fe4195b`. The enforcement lane owns `broker.rs`, supervisor binaries, sandbox
policy, durable execution records, cancellation, and recovery. This lane owns
patch proposals, frozen evaluation requirements, evidence binding, and workflow
tests. Neither lane changes the other's interface without a compatibility review.

## Existing interface and missing operations

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

## Integration exit gate

Run one useful single-file maintenance task in an isolated checkout. Independently
evaluate the exact proposed bytes against locked requirements and adversarial
tests. Bind acceptance to patch, baseline, evaluator executable, input, test,
and policy digests. Reject mismatches before mutation. Verify committed bytes
and untouched files; on failure restore the baseline and verify restoration.
Missing evidence or an expired lease must not release authority. Deliberate
path escapes, stale baselines, changed tests, receipt substitution, evaluator
failure, cancellation, and interrupted commits must be exercised against the
real broker before claiming enforced useful maintenance.

## Subsequent gates

1. Independent replication: a separate operator and host reproduce the exact
   frozen containment/recovery packet and sign their own results.
2. Shadow adaptation: candidate updates compete against an immutable baseline
   on locked evaluations; independent authority controls promotion and rollback.
3. Causal research: separately accepted preregistration, custody, identity, and
   spend gates precede interventions and held-out monitor evaluation.
4. External market: outsource the fixed job class only after independent receipt
   verification; escrow and settlement require their own authorization.

These produce distinct evidence for containment, bounded usefulness, replication,
controlled adaptation, causal effects, and outsourced computation. No individual
gate establishes general alignment. Model execution remains separately gated.
