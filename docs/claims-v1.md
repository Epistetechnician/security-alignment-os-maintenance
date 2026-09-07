# Meet-only claim envelopes V1

State slice: `security-alignment-os-foundation-v1`.

`claims::ClaimEnvelope` composes only by meet: guarantees are intersected,
assumptions and exclusions are unioned, evidence digests are unioned, and the
validity window is narrowed to the earlier expiry. Envelopes with different
state slices or claim ceilings cannot compose. A guarantee/exclusion conflict
is invalid.

`AggregateReleasePacket::from_envelopes` emits only claim IDs, evidence
digests, aggregate labels, and a digest-bound packet identity. Raw payloads are
rejected by construction and validation. This is an aggregate-only local
record; it does not authenticate evidence, prove truth, or authorize release.
