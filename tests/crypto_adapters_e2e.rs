//! End-to-end tests for the offline crypto-adapter contract.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! No wallet, key, network, provider, transaction, or value movement is used.

use security_alignment_os::crypto_adapters::{
    reconcile, AdapterEventKind, AdapterKind, AppendDisposition, ChainIdentity, CryptoJournal,
    DryRunAdapter, ObservationStatus, ReconciliationObservation, SettlementIntent,
    SettlementRequest,
};
use security_alignment_os::market;
use security_alignment_os::{digest, Error, STATE_SLICE};

fn setup() -> (
    SettlementIntent,
    DryRunAdapter,
    ReconciliationObservation,
    String,
) {
    let job = market::SumJob::new(
        "job-crypto-1".into(),
        "requester".into(),
        vec![2, 3, 5],
        100,
        0,
    )
    .expect("fixed job");
    let receipt = market::execute_local(&job, 10).expect("local receipt");
    let mut verifier = market::ReceiptVerifier::default();
    assert!(verifier.verify(&job, &receipt, 10).expect("verify receipt"));
    let proposal = verifier
        .propose_settlement(&job, &receipt, 10)
        .expect("authorization-required proposal");
    let chain = ChainIdentity {
        schema_version: 1,
        state_slice: STATE_SLICE.into(),
        adapter: AdapterKind::HyperliquidDryRun,
        adapter_revision: "hyperliquid-dry-run-v1".into(),
        chain_id: 998,
        contract_address: "local-escrow-contract".into(),
        asset: "test-credit-zero".into(),
    };
    let intent = SettlementIntent::from_market_proposal(
        &proposal,
        &job,
        &receipt,
        chain.clone(),
        SettlementRequest {
            intent_id: "intent-crypto-1".into(),
            payment_id: "payment-crypto-1".into(),
            beneficiary: proposal.provider.clone(),
            specification_digest: digest(&("fixed-job-spec", 1u8)).expect("spec digest"),
            artifact_digest: digest(&("artifact", 1u8)).expect("artifact digest"),
            accepted_evidence_digest: digest(&("accepted-evidence", 1u8)).expect("evidence digest"),
            policy_digest: digest(&("policy", 1u8)).expect("policy digest"),
            created_at: 10,
            expires_at: 90,
        },
    )
    .expect("settlement intent");
    let adapter = DryRunAdapter::new(chain).expect("dry-run adapter");
    let intent_digest = intent.digest().expect("intent digest");
    let observation = ReconciliationObservation {
        schema_version: 1,
        state_slice: STATE_SLICE.into(),
        observation_id: "observation-crypto-1".into(),
        adapter: intent.adapter,
        adapter_revision: intent.adapter_revision.clone(),
        intent_digest: intent_digest.clone(),
        payment_id: intent.payment_id.clone(),
        chain_id: intent.chain_id,
        contract_address: intent.contract_address.clone(),
        status: ObservationStatus::Observed,
        transaction_digest: Some(
            digest(&("dry-run-observation", &intent_digest)).expect("transaction digest"),
        ),
        observed_amount: 0,
        asset: intent.asset.clone(),
        beneficiary: intent.beneficiary.clone(),
        observed_at: 20,
    };
    (intent, adapter, observation, intent_digest)
}

#[test]
fn dry_run_adapter_replays_and_reconciles_without_authority() {
    let (intent, adapter, observation, intent_digest) = setup();
    let receipt = adapter.prepare(&intent, 20).expect("prepare dry run");
    assert!(!receipt.signed);
    assert!(!receipt.network_attempted);
    assert!(!receipt.value_moved);

    let result = reconcile(&intent, &observation).expect("matching observation");
    assert!(!result.payout_authorized);
    assert!(!result.signed);
    assert!(!result.network_attempted);
    assert!(!result.value_moved);

    let mut journal = CryptoJournal::default();
    assert_eq!(
        journal.append_proposed(&intent, 10).expect("propose"),
        AppendDisposition::Appended
    );
    assert_eq!(
        journal
            .append_prepared(&intent, &receipt, 20)
            .expect("prepare"),
        AppendDisposition::Appended
    );
    assert_eq!(
        journal
            .append_reconciled(&intent, &observation, &result, 20)
            .expect("reconcile"),
        AppendDisposition::Appended
    );
    assert_eq!(
        journal.state(&intent_digest).expect("journal state"),
        Some(AdapterEventKind::Reconciled)
    );
    assert_eq!(journal.events().len(), 3);

    assert_eq!(
        journal
            .append_proposed(&intent, 99)
            .expect("idempotent propose"),
        AppendDisposition::AlreadyPresent
    );
    assert_eq!(
        journal
            .append_prepared(&intent, &receipt, 99)
            .expect("idempotent prepare"),
        AppendDisposition::AlreadyPresent
    );
    assert_eq!(
        journal
            .append_reconciled(&intent, &observation, &result, 99)
            .expect("idempotent reconcile"),
        AppendDisposition::AlreadyPresent
    );
    journal.validate().expect("valid replay journal");
}

#[test]
fn every_supported_adapter_label_is_prepare_only() {
    let (base_intent, _, _, _) = setup();
    for adapter_kind in AdapterKind::all() {
        let mut intent = base_intent.clone();
        intent.adapter = adapter_kind;
        let adapter = DryRunAdapter::new(intent.chain_identity()).expect("dry-run adapter");
        let receipt = adapter.prepare(&intent, 20).expect("prepare dry run");
        assert_eq!(receipt.adapter, adapter_kind);
        assert!(!receipt.signed);
        assert!(!receipt.network_attempted);
        assert!(!receipt.value_moved);
    }
}

#[test]
fn ambiguous_observation_quarantines_and_terminal_state_cannot_advance() {
    let (intent, adapter, mut observation, _) = setup();
    observation.status = ObservationStatus::Ambiguous;
    observation.transaction_digest = None;
    let error = reconcile(&intent, &observation).expect_err("ambiguous observation");
    assert!(matches!(error, Error::Quarantined(_)));

    let receipt = adapter.prepare(&intent, 20).expect("prepare dry run");
    let mut journal = CryptoJournal::default();
    journal.append_proposed(&intent, 10).expect("propose");
    journal
        .append_quarantined(
            &intent,
            &observation.digest().expect("observation digest"),
            20,
        )
        .expect("quarantine");
    assert_eq!(
        journal
            .state(&intent.digest().expect("intent digest"))
            .expect("journal state"),
        Some(AdapterEventKind::Quarantined)
    );
    assert!(matches!(
        journal.append_prepared(&intent, &receipt, 20),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn mismatched_identity_and_nonzero_value_fail_closed() {
    let (intent, _, observation, _) = setup();
    let matching_result = reconcile(&intent, &observation).expect("matching result");
    let mut not_found = observation.clone();
    not_found.status = ObservationStatus::NotFound;
    not_found.transaction_digest = None;
    assert!(matches!(
        reconcile(&intent, &not_found),
        Err(Error::Rejected(_))
    ));
    let mut mismatched_observation = observation.clone();
    mismatched_observation.payment_id = "other-payment".into();
    assert!(matches!(
        reconcile(&intent, &mismatched_observation),
        Err(Error::Quarantined(_))
    ));

    let mut journal = CryptoJournal::default();
    journal.append_proposed(&intent, 10).expect("propose");
    assert!(matches!(
        journal.append_reconciled(&intent, &mismatched_observation, &matching_result, 20),
        Err(Error::Rejected(_))
    ));

    let mut nonzero = intent.clone();
    nonzero.amount = 1;
    assert!(matches!(nonzero.validate(), Err(Error::Invalid(_))));

    assert_eq!(
        journal
            .append_proposed(&intent, 10)
            .expect("idempotent propose"),
        AppendDisposition::AlreadyPresent
    );
    let mut conflicting = intent;
    conflicting.intent_id = "different-intent".into();
    assert!(matches!(
        journal.append_proposed(&conflicting, 10),
        Err(Error::Quarantined(_))
    ));
}

#[test]
fn journal_persistence_is_canonical_and_recovers_the_latest_snapshot() {
    let (intent, adapter, _, _) = setup();
    let receipt = adapter.prepare(&intent, 20).expect("prepare dry run");
    let mut journal = CryptoJournal::default();
    journal.append_proposed(&intent, 10).expect("propose");
    journal
        .append_prepared(&intent, &receipt, 20)
        .expect("prepare");

    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("crypto-journal.json");
    journal.save(&path).expect("save journal");
    let loaded = CryptoJournal::load(&path).expect("load journal");
    assert_eq!(loaded.events(), journal.events());

    let temporary = path.with_extension("tmp");
    std::fs::rename(&path, &temporary).expect("move primary to temporary");
    let recovered = CryptoJournal::recover(&path).expect("recover journal");
    assert_eq!(recovered.events(), journal.events());
    assert!(path.exists());
    assert!(!temporary.exists());
}
