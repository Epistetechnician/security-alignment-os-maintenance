//! Cross-module end-to-end contract test for the foundation slice.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! No model, provider, network, wallet, or payment operation is performed.

use security_alignment_os::adaptation::{AdaptationEvidence, AdaptationRecord};
use security_alignment_os::broker::{transform_output, FileTransformOperation};
use security_alignment_os::causal::{CausalProtocol, CausalProtocolInputs, CausalTrack};
use security_alignment_os::execution_gate::{
    ExecutionGate, ExternalExecutionRequest, GateDisposition, SandboxAttestation,
};
use security_alignment_os::market::{self, SettlementStatus};
use security_alignment_os::replication::{
    compare, FrozenReplicationPacket, ReplicationResult, ReplicationSigner, ReplicationTerminal,
};
use security_alignment_os::{digest_bytes, STATE_SLICE};

fn digest(value: u8) -> String {
    format!("{value:064x}")
}

#[test]
fn local_platform_sequence_preserves_claim_boundaries() {
    let input = b"# bounded maintenance  \n";
    let output = transform_output(FileTransformOperation::TrimTrailingAsciiSpaces, input)
        .expect("fixed maintenance transform");
    assert_eq!(output, b"# bounded maintenance\n");

    let packet = FrozenReplicationPacket::new(
        "maintenance-packet-1",
        digest(1),
        digest(2),
        digest(3),
        digest(4),
        digest(5),
        ReplicationTerminal::Completed,
        Some(digest_bytes(&output)),
        digest_bytes(input),
        digest(6),
        digest(7),
        false,
        ["local-test-host".into()].into_iter().collect(),
        100,
    )
    .expect("frozen packet");
    let signer = ReplicationSigner::from_seed("replication-key-b", [9; 32]).expect("signer");
    let result = ReplicationResult::new(
        &packet,
        "operator-b",
        "host-b",
        ReplicationTerminal::Completed,
        Some(digest_bytes(&output)),
        digest_bytes(input),
        digest(6),
        digest(7),
        false,
        10,
    )
    .expect("replication result");
    let signed = signer.sign(result).expect("signed replication result");
    assert_eq!(
        compare(
            &packet,
            &signed,
            signer.key_id(),
            signer.verifying_key_bytes()
        )
        .expect("replication comparison"),
        security_alignment_os::replication::ReplicationDisposition::Matched
    );

    let mut adaptation = AdaptationRecord::new(
        "candidate-1",
        "proposer",
        digest(11),
        digest(12),
        digest(13),
        digest(14),
        digest(15),
        digest(16),
        digest(17),
        digest(18),
        "promotion-authority",
    )
    .expect("adaptation record");
    adaptation
        .record_shadow(&AdaptationEvidence {
            reviewer_id: "reviewer".into(),
            promotion_authority_id: "promotion-authority".into(),
            evaluator_digest: digest(14),
            evidence_digest: digest(19),
            stream_digest: digest(20),
            resource_usage_digest: digest(21),
            healthy: true,
        })
        .expect("shadow evidence");
    adaptation
        .record_canary(&AdaptationEvidence {
            reviewer_id: "reviewer".into(),
            promotion_authority_id: "promotion-authority".into(),
            evaluator_digest: digest(14),
            evidence_digest: digest(22),
            stream_digest: digest(23),
            resource_usage_digest: digest(24),
            healthy: true,
        })
        .expect("canary evidence");
    adaptation
        .promote("promotion-authority", &digest(25))
        .expect("independent promotion");

    let mut causal = CausalProtocol::new(CausalProtocolInputs {
        protocol_id: "causal-1".into(),
        researcher_id: "researcher".into(),
        validator_id: "validator".into(),
        track: CausalTrack::Behavioral,
        model_digest: digest(31),
        runtime_digest: digest(32),
        asset_manifest_digest: digest(33),
        corpus_digest: digest(34),
        split_digest: digest(35),
        held_out_split_digest: digest(36),
        wrapper_digest: digest(37),
        feature_digest: digest(38),
        estimand_digest: digest(39),
        intervention_digest: digest(40),
        control_digest: digest(41),
        power_digest: digest(42),
        multiplicity_digest: digest(43),
        repeat_digest: digest(44),
        attrition_digest: digest(45),
        prediction_lock_digest: digest(46),
        custody_digest: digest(47),
        validator_config_digest: digest(48),
        raw_trace_retention_until: 100,
    })
    .expect("causal protocol");
    causal.qualify(&digest(49)).expect("qualification");
    causal
        .lock_assessment(&digest(50), &digest(46))
        .expect("prediction lock");
    causal
        .accept_independently("validator", &digest(51))
        .expect("independent causal acceptance");
    assert!(causal.assessment_eligible());

    let job = market::SumJob::new("job-1".into(), "requester".into(), vec![2, 3, 5], 100, 0)
        .expect("fixed job");
    let receipt = market::execute_local(&job, 10).expect("local receipt");
    let mut verifier = market::ReceiptVerifier::default();
    assert!(verifier.verify(&job, &receipt, 10).expect("verify receipt"));
    let settlement = verifier
        .propose_settlement(&job, &receipt, 10)
        .expect("authorization-required settlement proposal");
    assert_eq!(settlement.status, SettlementStatus::AuthorizationRequired);

    let attestation = SandboxAttestation {
        attestation_id: "local-attestation".into(),
        executor_digest: digest(60),
        egress_denied: true,
        secret_broker: true,
        independent_kill_path: true,
        memory_bytes: 1,
        cpu_ms: 1,
        issued_at: 0,
        expires_at: 100,
    };
    let request = ExternalExecutionRequest {
        request_id: "external-request".into(),
        program_digest: digest(61),
        input_digest: digest(62),
        output_schema_digest: digest(63),
        proof_system: "fixed-local-receipt".into(),
        privacy_requirement: "none".into(),
        requested_at: 0,
        deadline: 100,
        max_price: 0,
    };
    let decision = ExecutionGate::new()
        .authorize(&attestation, &request, 10)
        .expect("closed external gate");
    assert_eq!(decision.disposition, GateDisposition::Blocked);
    assert_eq!(STATE_SLICE, "security-alignment-os-foundation-v1");
}
