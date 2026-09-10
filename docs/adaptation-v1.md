# Controlled shadow adaptation V1

State slice: `security-alignment-os-foundation-v1`.

`adaptation::AdaptationRecord` freezes one immutable base and candidate with
the training-data manifest, evaluator, policy, resource budget, evaluation
lock, canary policy, promotion authority, and rollback target digests. The
proposer and promotion authority must be distinct. Shadow and canary evidence
must use the frozen evaluator and independent reviewer identities; promotion
requires a separate authority decision.

The local lifecycle is `Shadow -> Canary -> CandidateApproved -> ReleasedLocal`.
Rollback and freeze are terminal dispositions for the affected record. Phase
evidence is unique and state-bound. Canonical persistence detects modified
records, but it does not deploy a candidate, serve traffic, train a model, or
authenticate the role strings.

The claim ceiling is `ControlledLocalShadowAdaptation`; it is not evidence of
alignment, generalization, production safety, or human benefit.
