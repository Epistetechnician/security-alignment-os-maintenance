//! End-to-end tests for the offline crypto-adapter contract.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! No wallet, key, network, provider, transaction, or value movement is used.

use ed25519_dalek::{Signer, SigningKey};
use security_alignment_os::artifacts::{ArtifactManifest, ArtifactRegistry};
use security_alignment_os::crypto_adapters::{
    reconcile, AdapterEventKind, AdapterKind, AppendDisposition, ChainIdentity, CryptoJournal,
    DryRunAdapter, ObservationStatus, PayoutProposal, ProviderKeyRegistry,
    ProviderObservationEnvelope, ReconciliationObservation, SettlementIntent,
    SettlementIntentContext, SettlementRequest, SettlementResolution, WireEnvelope,
};
use security_alignment_os::market;
use security_alignment_os::{digest, Error, Evidence, EvidenceRegistry, STATE_SLICE};

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
    let receipt_digest = digest(&receipt).expect("receipt digest");
    let mut evidence = EvidenceRegistry::default();
    evidence
        .insert(Evidence {
            id: "evidence-crypto-1".into(),
            source_digest: receipt_digest,
            operator_id: "operator-crypto".into(),
            validator_id: "validator-crypto".into(),
            reviewer_id: "reviewer-crypto".into(),
            valid_until: 90,
            accepted: true,
            revoked: false,
        })
        .expect("accepted evidence");
    let evidence_record_digest = evidence
        .record_digest("evidence-crypto-1")
        .expect("evidence record digest");
    let manifest = ArtifactManifest {
        artifact_id: "artifact-crypto-1".into(),
        subject_digest: evidence_record_digest.clone(),
        source_digest: digest(&("artifact-source", 1u8)).expect("artifact source digest"),
        license: "MIT".into(),
        provenance_digest: digest(&("artifact-provenance", 1u8)).expect("provenance digest"),
        custody_root: "/tmp/crypto-adapter-custody".into(),
        retention_start: 0,
        retention_until: 90,
    };
    let mut artifacts = ArtifactRegistry::default();
    artifacts
        .quarantine(manifest, "artifact-operator", "artifact-validator")
        .expect("quarantined artifact");
    artifacts
        .accept(
            "artifact-crypto-1",
            &evidence_record_digest,
            "artifact-reviewer",
            10,
        )
        .expect("accepted artifact");
    let chain = ChainIdentity {
        schema_version: 1,
        state_slice: STATE_SLICE.into(),
        adapter: AdapterKind::HyperliquidDryRun,
        adapter_revision: "hyperliquid-dry-run-v1".into(),
        chain_id: 998,
        contract_address: "local-escrow-contract".into(),
        asset: "test-credit-zero".into(),
    };
    let intent = SettlementIntent::from_market_proposal(SettlementIntentContext {
        proposal: &proposal,
        job: &job,
        receipt: &receipt,
        chain: chain.clone(),
        evidence: &evidence,
        evidence_id: "evidence-crypto-1",
        artifacts: &artifacts,
        artifact_id: "artifact-crypto-1",
        request: SettlementRequest {
            intent_id: "intent-crypto-1".into(),
            payment_id: "payment-crypto-1".into(),
            beneficiary: proposal.provider.clone(),
            specification_digest: digest(&("fixed-job-spec", 1u8)).expect("spec digest"),
            policy_digest: digest(&("policy", 1u8)).expect("policy digest"),
            created_at: 10,
            expires_at: 90,
        },
    })
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

fn signed_provider_observation(
    observation: ReconciliationObservation,
) -> (ProviderKeyRegistry, ProviderObservationEnvelope, SigningKey) {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let mut keys = ProviderKeyRegistry::default();
    keys.insert(
        "provider-key-crypto-1",
        signing_key.verifying_key().to_bytes().to_vec(),
    )
    .expect("provider key");
    let mut envelope = ProviderObservationEnvelope::unsigned(
        observation.beneficiary.clone(),
        "provider-key-crypto-1",
        observation,
    )
    .expect("unsigned provider observation");
    envelope.signature = signing_key
        .sign(&envelope.signing_bytes().expect("provider signing bytes"))
        .to_bytes()
        .to_vec();
    let bytes = envelope.encode().expect("canonical provider envelope");
    let decoded = ProviderObservationEnvelope::decode(&bytes).expect("decode provider envelope");
    assert_eq!(decoded, envelope);
    let mut noncanonical = bytes.clone();
    noncanonical.insert(0, b' ');
    assert!(matches!(
        ProviderObservationEnvelope::decode(&noncanonical),
        Err(Error::Journal(_))
    ));
    let bytes_as_text = String::from_utf8(bytes).expect("provider envelope UTF-8");
    let duplicate_key = bytes_as_text.replace(
        "\"provider_id\":\"local-sum\"",
        "\"provider_id\":\"local-sum\",\"provider_id\":\"local-sum\"",
    );
    assert_ne!(duplicate_key, bytes_as_text);
    assert!(matches!(
        ProviderObservationEnvelope::decode(duplicate_key.as_bytes()),
        Err(Error::Journal(_))
    ));
    (keys, envelope, signing_key)
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
    let resolution = SettlementResolution::from_reconciliation(&intent, &observation, &result)
        .expect("authorization-required resolution");
    assert_eq!(
        resolution.status,
        security_alignment_os::crypto_adapters::AuthorizationStatus::AuthorizationRequired
    );
    assert!(!resolution.payout_authorized);
    let payout = PayoutProposal::from_resolution(&intent, &resolution)
        .expect("authorization-required payout proposal");
    assert!(!payout.payout_authorized);
    assert_eq!(payout.amount, 0);
    let mut forged_resolution = resolution.clone();
    forged_resolution.payout_authorized = true;
    assert!(matches!(
        forged_resolution.validate(&intent, &observation, &result),
        Err(Error::Rejected(_))
    ));
    let mut forged_payout = payout.clone();
    forged_payout.amount = 1;
    assert!(matches!(
        forged_payout.validate(&intent, &resolution),
        Err(Error::Rejected(_))
    ));

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
        journal
            .append_payout_proposed(&intent, &resolution, &payout, 20)
            .expect("payout proposal"),
        AppendDisposition::Appended
    );
    assert_eq!(
        journal.state(&intent_digest).expect("journal state"),
        Some(AdapterEventKind::PayoutProposed)
    );
    assert_eq!(journal.events().len(), 4);
    security_alignment_os::checker::validate_crypto_journal(&journal)
        .expect("independent journal check");

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
    assert_eq!(
        journal
            .append_payout_proposed(&intent, &resolution, &payout, 99)
            .expect("idempotent payout proposal"),
        AppendDisposition::AlreadyPresent
    );
    journal.validate().expect("valid replay journal");
}

#[test]
fn signed_provider_observation_is_verified_before_reconciliation() {
    let (intent, _, observation, _) = setup();
    let (keys, envelope, signing_key) = signed_provider_observation(observation.clone());
    assert_eq!(
        envelope
            .verify(&keys, &intent)
            .expect("verified observation"),
        observation
    );
    let result = envelope
        .verify_and_reconcile(&keys, &intent)
        .expect("verified reconciliation");
    assert!(!result.payout_authorized);
    assert!(!result.network_attempted);
    assert!(!result.value_moved);

    let mut forged_signature = envelope.clone();
    forged_signature.signature[0] ^= 1;
    assert!(matches!(
        forged_signature.verify(&keys, &intent),
        Err(Error::Rejected(_))
    ));

    let mut forged_observation = envelope.clone();
    forged_observation.observation.payment_id = "other-payment".into();
    assert!(matches!(
        forged_observation.verify(&keys, &intent),
        Err(Error::Invalid(_))
    ));

    let mut revoked_keys = keys.clone();
    revoked_keys
        .revoke("provider-key-crypto-1")
        .expect("revoke provider key");
    assert!(matches!(
        envelope.verify(&revoked_keys, &intent),
        Err(Error::Rejected(_))
    ));

    let mut unknown_key = ProviderObservationEnvelope::unsigned(
        observation.beneficiary.clone(),
        "unknown-provider-key",
        observation,
    )
    .expect("unknown-key envelope");
    unknown_key.signature = signing_key
        .sign(
            &unknown_key
                .signing_bytes()
                .expect("unknown-key signing bytes"),
        )
        .to_bytes()
        .to_vec();
    assert!(matches!(
        unknown_key.verify(&keys, &intent),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn provider_key_registry_persists_canonically_and_recovers() {
    let (keys, _, _) = signed_provider_observation(setup().2);
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("provider-keys.json");
    keys.save(&path).expect("save provider keys");
    let loaded = ProviderKeyRegistry::load(&path).expect("load provider keys");
    loaded.validate().expect("valid loaded keys");

    let temporary = path.with_extension("tmp");
    std::fs::rename(&path, &temporary).expect("move provider keys to temporary");
    let recovered = ProviderKeyRegistry::recover(&path).expect("recover provider keys");
    recovered.validate().expect("valid recovered keys");
    assert!(path.exists());
    assert!(!temporary.exists());
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
fn provider_wire_envelopes_round_trip_only_as_canonical_dry_runs() {
    let (base_intent, _, _, _) = setup();
    for adapter_kind in AdapterKind::all() {
        let mut intent = base_intent.clone();
        intent.adapter = adapter_kind;
        let adapter = DryRunAdapter::new(intent.chain_identity()).expect("dry-run adapter");
        let envelope = adapter.prepare_wire(&intent).expect("wire envelope");
        let bytes = envelope.encode().expect("canonical wire bytes");
        let decoded = WireEnvelope::decode(adapter_kind, &bytes).expect("decode wire bytes");
        decoded.validate(&intent).expect("wire binding");
        assert_eq!(decoded.adapter(), adapter_kind);

        let mut noncanonical = bytes.clone();
        noncanonical.insert(0, b' ');
        assert!(matches!(
            WireEnvelope::decode(adapter_kind, &noncanonical),
            Err(Error::Journal(_))
        ));

        let bytes_as_text = String::from_utf8(bytes).expect("wire UTF-8");
        let duplicate_key = bytes_as_text.replace(
            "\"action\":\"prepare-only-v1\"",
            "\"action\":\"prepare-only-v1\",\"action\":\"prepare-only-v1\"",
        );
        assert_ne!(duplicate_key, bytes_as_text);
        assert!(matches!(
            WireEnvelope::decode(adapter_kind, duplicate_key.as_bytes()),
            Err(Error::Journal(_))
        ));
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
    security_alignment_os::checker::validate_crypto_journal(&loaded)
        .expect("independent loaded journal check");

    let temporary = path.with_extension("tmp");
    std::fs::rename(&path, &temporary).expect("move primary to temporary");
    let recovered = CryptoJournal::recover(&path).expect("recover journal");
    assert_eq!(recovered.events(), journal.events());
    assert!(path.exists());
    assert!(!temporary.exists());
}
