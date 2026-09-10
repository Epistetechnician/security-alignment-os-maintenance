# Crypto-adapter contracts V2

State slice: `security-alignment-os-foundation-v1`.

V2 hardens the V1 offline adapter seam without opening an external integration.
It replaces caller-only settlement evidence with registry-backed eligibility
and adds strict provider-shaped wire envelopes for the three dry-run labels.

## Registry-backed eligibility

`SettlementIntent::from_market_proposal` now requires:

- the exact `market::SettlementProposal`, `SumJob`, and `SumReceipt`;
- an accepted, live `EvidenceRegistry` record whose source is the receipt
  digest;
- an accepted, live `ArtifactRegistry` record whose subject is the evidence
  record digest; and
- a bounded request containing the intent, payment, beneficiary,
  specification, policy, and time-window fields.

The intent derives `evidence_digest`, `artifact_digest`, and
`eligibility_digest` from those validated records. Callers cannot substitute
arbitrary evidence or artifact digests through this constructor. Role fields,
acceptance, retention, and revocation remain caller assertions in the existing
local registries and are not authenticated external authority.

## Provider-shaped canonical wire envelopes

`DryRunAdapter::prepare_wire` emits one typed `WireEnvelope` variant:

- `Hyperliquid` binds a dry-run order type and deterministic client-order ID;
- `EvmEscrow` binds a dry-run method and deterministic calldata digest; and
- `Tempo` binds a deterministic payment-memo digest.

Every envelope repeats the exact intent, payment, chain, contract, asset,
beneficiary, zero amount, adapter revision, claim ceiling, and prepare-only
flags. All variants require `signed = false`, `network_attempted = false`, and
`value_moved = false`.

`WireEnvelope::encode` emits canonical JSON. `WireEnvelope::decode` rejects
duplicate object keys before deserialization, rejects malformed JSON and
noncanonical bytes, enforces the requested adapter discriminator, and checks
the envelope digest. `validate` then recomputes the provider-specific field
from the intent digest. No provider SDK or chain-specific signing algorithm is
implemented here.

## Independent verification

`checker::validate_crypto_journal` independently recomputes the event shape,
hash chain, one-key-per-intent rule, duplicate identities, and legal
transitions without calling `CryptoJournal::validate`. The adapter tests cover
all three wire variants, canonical round trips, duplicate-key rejection,
noncanonical bytes, registry-backed intent construction, ambiguity quarantine,
nonzero-value rejection, idempotent replay, and journal recovery.

## Claim ceiling

The implementation remains:

> local Rust pure-data control and caller-owned persistence evidence only

It does not create wallets, store private keys, sign, contact RPC/provider
endpoints, observe authoritative chain state, submit transactions, move value,
or authorize payout. A matching dry-run wire envelope or reconciliation record
is not proof of an external transaction or provider result.
