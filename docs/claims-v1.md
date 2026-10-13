# Meet-only claim envelopes V1

State slice: `security-alignment-os-foundation-v1`.

`claims::ClaimEnvelope` composes only by meet: guarantees are intersected,
assumptions and exclusions are unioned, evidence digests are unioned, and the
validity window is narrowed to the earlier expiry. Envelopes with different
state slices or claim ceilings cannot compose. A guarantee/exclusion conflict
is invalid.

`AggregateReleasePacket::from_envelopes` requires one `ClaimEvidenceBinding`
for every envelope and checks each evidence ID against the local
`EvidenceRegistry`. Every record must be accepted, unrevoked, current, bound to
the supplied subject digest, and valid through the claim's full validity
interval. The record digests in the envelope must match those registry records
exactly.

The packet commits each claim ID to the complete canonical envelope digest and
retains per-claim evidence and subject digests. `validate_current` recomputes
the claim commitments and checks that each evidence record is still accepted,
current, and subject-bound. Revocation, expiry, claim edits, subject
substitution, and evidence replacement invalidate the packet. Raw payloads
remain excluded by construction and validation.

This is local evidence-registry enforcement only. Reviewer/operator/validator
identities remain caller assertions; the packet does not authenticate people,
verify physical custody or deletion, prove evidence truth, publish a public
claim, or authorize deployment or production.
