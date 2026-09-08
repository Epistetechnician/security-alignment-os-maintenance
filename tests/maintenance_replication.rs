//! Separate-host replication contract checks.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use ed25519_dalek::SigningKey;
use security_alignment_os::digest_bytes;
use security_alignment_os::maintenance_process::{
    fixed_input_digest, fixed_policy_digest, fixed_tests_digest,
};

fn public_key_hex(seed: u8) -> String {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
use security_alignment_os::maintenance_replication::{
    HostReport, RecoveryDisposition, ReplicationPacket, ScenarioResult, ScenarioStatus,
    FIXED_OPERATION_IDENTITY, REPLICATION_CLAIM_CEILING, REPLICATION_VERSION, REQUIRED_SCENARIOS,
};

fn scenarios(baseline: &str) -> Vec<ScenarioResult> {
    REQUIRED_SCENARIOS
        .iter()
        .enumerate()
        .map(|(index, scenario_id)| {
            let (status, recovery, final_checkout_digest) = match *scenario_id {
                "authorized-completion" => (
                    ScenarioStatus::Applied,
                    RecoveryDisposition::AuthorizedChangeCommitted,
                    "b".repeat(64),
                ),
                "evaluation-expiry" => (
                    ScenarioStatus::Quarantined,
                    RecoveryDisposition::NoMutation,
                    baseline.to_owned(),
                ),
                "pre-finalization-cancellation" | "pre-finalization-expiry" => (
                    ScenarioStatus::RolledBack,
                    RecoveryDisposition::BaselineRestored,
                    baseline.to_owned(),
                ),
                "concurrent-target-change" | "neighbor-change-recovery" => (
                    ScenarioStatus::Frozen,
                    RecoveryDisposition::ExternalChangePreservedAndFrozen,
                    "c".repeat(64),
                ),
                "shared-checkout-lock" | "replacement-lock-ownership" => (
                    ScenarioStatus::Blocked,
                    RecoveryDisposition::NoMutation,
                    baseline.to_owned(),
                ),
                other => panic!("unhandled scenario {other}"),
            };
            ScenarioResult {
                scenario_id: (*scenario_id).into(),
                status,
                recovery,
                final_checkout_digest,
                evidence_digest: digest_bytes(format!("host-evidence-{index}").as_bytes()),
            }
        })
        .collect()
}

fn report(seed: u8, host_id: &str, operator_id: &str) -> HostReport {
    let mut report = HostReport {
        version: REPLICATION_VERSION,
        state_slice: "security-alignment-os-foundation-v1".into(),
        operation: FIXED_OPERATION_IDENTITY.into(),
        process_version: 2,
        implementation_revision: "3c19d80".to_owned() + &"0".repeat(33),
        request_digest: "d".repeat(64),
        checkout_baseline_digest: "a".repeat(64),
        evaluator_executable_digest: "b".repeat(64),
        evaluator_input_digest: fixed_input_digest(),
        evaluator_tests_digest: fixed_tests_digest(),
        policy_digest: fixed_policy_digest(),
        evaluator_public_key: public_key_hex(9),
        evaluator_timeout_ms: 10_000,
        claim_ceiling: REPLICATION_CLAIM_CEILING.into(),
        host_id: host_id.into(),
        operator_id: operator_id.into(),
        host_public_key: String::new(),
        operator_public_key: String::new(),
        scenarios: scenarios(&"a".repeat(64)),
        report_id: String::new(),
        host_signature: String::new(),
        operator_signature: String::new(),
    };
    report
        .sign_with_seeds([seed; 32], [seed + 10; 32])
        .expect("signed report");
    report
}

#[test]
fn two_signed_reports_round_trip_as_canonical_packet() {
    let packet = ReplicationPacket::from_reports(vec![
        report(1, "host-a", "operator-a"),
        report(2, "host-b", "operator-b"),
    ])
    .expect("packet");

    packet.validate().expect("valid packet");
    let bytes = packet.canonical_bytes().expect("canonical packet");
    assert_eq!(
        ReplicationPacket::from_canonical_bytes(&bytes).expect("round trip"),
        packet
    );
}

#[test]
fn same_declared_host_is_not_independent() {
    let first = report(1, "host-a", "operator-a");
    let mut second = report(2, "host-a", "operator-b");
    second.host_id = first.host_id.clone();
    assert!(ReplicationPacket::from_reports(vec![first, second]).is_err());
}

#[test]
fn same_declared_operator_or_key_is_not_independent() {
    let first = report(1, "host-a", "operator-a");
    let same_operator = report(2, "host-b", "operator-a");
    assert!(ReplicationPacket::from_reports(vec![first.clone(), same_operator.clone()]).is_err());

    let same_key = report(1, "host-b", "operator-b");
    assert!(ReplicationPacket::from_reports(vec![first, same_key]).is_err());
}

#[test]
fn evidence_substitution_after_signing_is_rejected() {
    let first = report(1, "host-a", "operator-a");
    let mut second = report(2, "host-b", "operator-b");
    second.scenarios[0].evidence_digest = "e".repeat(64);
    assert!(second.validate().is_err());
    assert!(ReplicationPacket::from_reports(vec![first, second]).is_err());
}

#[test]
fn inconsistent_recovery_result_is_rejected() {
    let mut first = report(1, "host-a", "operator-a");
    first.scenarios[1].final_checkout_digest = "b".repeat(64);
    assert!(first.validate().is_err());
}

#[test]
fn claim_ceiling_tampering_is_rejected() {
    let mut first = report(1, "host-a", "operator-a");
    first.claim_ceiling = "unbounded maintenance authority".into();
    assert!(first.validate().is_err());
}

#[test]
fn duplicate_keys_and_noncanonical_whitespace_are_rejected() {
    let packet = ReplicationPacket::from_reports(vec![
        report(1, "host-a", "operator-a"),
        report(2, "host-b", "operator-b"),
    ])
    .expect("packet");
    let bytes = packet.canonical_bytes().expect("canonical packet");
    let text = String::from_utf8(bytes.clone()).expect("json");
    let duplicate = text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(ReplicationPacket::from_canonical_bytes(duplicate.as_bytes()).is_err());

    let mut padded = Vec::with_capacity(bytes.len() + 1);
    padded.push(b' ');
    padded.extend(bytes);
    assert!(ReplicationPacket::from_canonical_bytes(&padded).is_err());
}

#[test]
fn reports_must_bind_the_same_fixed_request_and_revision() {
    let first = report(1, "host-a", "operator-a");
    let mut second = report(2, "host-b", "operator-b");
    second.request_digest = "f".repeat(64);
    second
        .sign_with_seeds([2; 32], [12; 32])
        .expect("resigned report");
    assert!(ReplicationPacket::from_reports(vec![first, second]).is_err());
}
