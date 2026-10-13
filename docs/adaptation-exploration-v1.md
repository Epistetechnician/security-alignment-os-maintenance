# Proposal-only adaptation exploration V1

State slice: `security-alignment-os-foundation-v1`.

This is an exploratory layer above the reviewed maintenance broker. It ranks
candidate updates from caller-supplied local evidence and deterministically
selects a local work offer. It does not mutate a checkout, approve an update,
execute external work, settle a price, or establish an independent-host or
scientific result.

## Contract

`adaptation::EvidenceAnchor` binds evidence, source, and immutable-base
digests to the foundation claim ceiling. `Inconclusive` or expired evidence
returns `NoCandidate`; it is never treated as a passing proxy.

`adaptation::AdaptationCandidate` wraps the existing immutable-base governance
candidate. Its rollback digest must equal its base digest, its evidence digest
must match the anchor, and its execution-authority bit must remain false.

`adaptation::select_plan` validates the complete candidate set and chooses by
priority, then immutable-base digest, then candidate digest. The resulting
`AdaptationPlan` is proposal-only and cannot authorize deployment.

`AdaptationPlan::stage_shadow` can pass the exactly bound candidate to the
existing governance registry. It creates only a `Shadow` record; a different
candidate is rejected, and no deployment or execution authority is created.

`adaptation::select_work_offer` validates offers against the exact plan and
selects by price, provider, and offer ID. Duplicate eligible offer identities
quarantine the selection. The function produces no settlement record and does
not contact a provider.

## Evidence ceiling

The module is suitable for deterministic local fixtures and shadow-mode
exploration. The current Host A report remains local-only evidence, and the
unfinished Host A/Host B replication gate is not bypassed. Promotion requires
the existing governance lifecycle plus the separate authenticated replication
and review gates.

## Verification

The module tests deterministic replay, inconclusive and expired evidence,
immutable-base binding, execution-authority rejection, offer tie-breaking,
duplicate-offer quarantine, and offer expiry. Passing local tests establish
only local Rust contract evidence.
