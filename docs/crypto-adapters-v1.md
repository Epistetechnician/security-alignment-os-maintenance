# Offline crypto-adapter contracts V1

State slice: `security-alignment-os-foundation-v1`.

This document records the implemented local adapter seam. It is a pure-data
contract and not a chain integration. The adapter names are stable labels for
future, separately reviewed implementations: `HyperliquidDryRun`,
`EvmEscrowDryRun`, and `TempoDryRun`.

## Implemented path

1. `market::ReceiptVerifier` verifies a fixed local receipt and emits a
   `SettlementProposal` with status `AuthorizationRequired`.
2. `crypto_adapters::SettlementIntent::from_market_proposal` requires that
   exact proposal, an accepted-evidence digest, specification/artifact/policy
   digests, a chain identity, a payment ID, a beneficiary, and a bounded time
   window. It binds the job, receipt, chain ID, contract address, asset, and
   payment identity. The amount is structurally fixed at zero.
3. `DryRunAdapter::prepare` emits a deterministic `DryRunReceipt`. The record
   binds the intent and adapter revision while asserting `signed = false`,
   `network_attempted = false`, and `value_moved = false`.
4. `reconcile` compares a caller-supplied observation against the frozen
   intent. Only an exact, zero-value `Observed` record produces
   `ReconciliationStatus::Matched`. `NotFound` is rejected; `Ambiguous` and
   identity/asset/beneficiary mismatches are quarantined.
5. `CryptoJournal` appends `Proposed`, `DryRunPrepared`, `Reconciled`, or
   `Quarantined` events to a canonical hash chain. It enforces per-intent
   transitions, one idempotency key per intent, terminal states, canonical
   persistence, and recovery of a valid temporary snapshot. Replaying the
   same event returns `AlreadyPresent` without appending a second record.

The journal is a caller-owned local record. `Reconciled` means only that the
caller-provided observation matched the zero-value intent; it is not a payout
authorization and cannot be used to obtain one from this crate.

## Boundaries and claim ceiling

This slice creates no wallet, stores no private key, performs no signing,
opens no socket, calls no RPC or provider API, submits no transaction, and
moves no value. It does not prove that a chain event happened, that a provider
completed computation, that evidence is independently accepted, or that a
beneficiary controls an address. `accepted_evidence_digest` is a caller
assertion that must be connected to an independently reviewed evidence plane
by a later authority-bearing slice.

The claim ceiling remains:

> local Rust pure-data control and caller-owned persistence evidence only

Testnet configuration, real chain reads, transaction signing, escrow release,
payment-provider settlement, dispute handling, authenticated custody, and
production authority remain separate gates. A testnet event, a price, a proof,
or an adapter receipt cannot release payment by itself.

No implementation code, scientific data, traces, credentials, or private data
was copied from `hyperIntel`, `hyperAI`, or `hypersacredai`. The repository's
source-intake record contains the consulted revisions and exact local
provenance status.

## Verification

`tests/crypto_adapters_e2e.rs` covers the complete local path, all three adapter
labels, ambiguity quarantine, identity mismatch, nonzero-value rejection,
idempotent replay, canonical persistence, and temporary-journal recovery. The
root verification command remains `pnpm run lint`.
