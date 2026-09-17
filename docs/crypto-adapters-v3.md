# Offline provider receipt authentication V3

State slice: `security-alignment-os-foundation-v1`.

V3 adds an offline authenticity boundary for provider observations. It accepts
only canonical, Ed25519-signed observation envelopes whose key is present and
not revoked in a caller-owned `ProviderKeyRegistry`. This authenticates a
signed byte sequence under the supplied key registry; it does not authenticate
the provider, chain state, address ownership, or computation correctness.

## Key registry

`ProviderKeyRegistry` stores public keys by explicit key ID, rejects malformed
or duplicate identities, supports terminal revocation, and persists through a
canonical JSON document with temporary-file recovery. It stores no private key
and has no signing operation. Key IDs and trust assertions remain caller-owned
inputs until a separately authorized trust root is added.

## Signed observation envelope

`ProviderObservationEnvelope::unsigned` constructs the canonical payload around
one `ReconciliationObservation`. `signing_bytes` returns the canonical payload
with an empty signature field; a separately controlled signer may produce the
signature outside this crate. `encode` and `decode` apply canonical JSON and
duplicate-key rejection before a verifier consumes the envelope.

`verify` requires:

- a valid envelope and exact observation digest;
- a trusted, non-revoked key ID;
- a valid Ed25519 signature over the canonical unsigned payload;
- provider ID equal to the observation beneficiary; and
- exact adapter, intent, payment, chain, contract, asset, and beneficiary
  identity binding to the frozen settlement intent; and
- an observation timestamp inside the settlement intent's inclusive/exclusive
  `[created_at, expires_at)` window.

`verify_and_reconcile` performs that verification before invoking the existing
zero-value reconciliation path. `checker::validate_provider_observation_envelope`
recomputes the same binding and signature equations through a separate checker
path. `NotFound` remains rejected and `Ambiguous` remains quarantined after
successful signature verification. A valid signature does not authorize a
payout.

Authorization-required resolutions and payout proposals recompute their stored
digests during shape validation. Editing either digest without recomputing the
canonical record is rejected before the proposal can enter the local journal.
The append-only journal also rejects backward event timestamps and preserves
its prior state if a new event fails final validation.

## Claim ceiling

The implementation remains:

> local Rust pure-data control and caller-owned persistence evidence only

It does not contact a provider or chain, resolve a public key from a network,
store a wallet or private key, sign, submit a transaction, move value, or prove
that a provider produced a truthful observation. The trusted-key registry and
provider identity are local assertions requiring a later external trust and
custody gate.

## Verification

`tests/crypto_adapters_e2e.rs` covers active-key verification before
reconciliation, signature tampering, observation tampering, unknown and
revoked keys, canonical signed-envelope round trips, duplicate-key rejection,
and key-registry persistence/recovery. The root verification command remains
`pnpm run lint`.
