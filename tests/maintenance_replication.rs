//! Separate-host replication contract checks.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use ed25519_dalek::SigningKey;
use security_alignment_os::maintenance_process::{
    fixed_input_digest, fixed_policy_digest, fixed_tests_digest, Request,
};
use security_alignment_os::maintenance_replication::{
    baseline_manifest_digest, BaselineManifestEntry, HostReport, ManifestFileKind,
    RecoveryDisposition, ReplicationPacket, ScenarioResult, ScenarioRole, ScenarioStatus,
    FIXED_OPERATION_IDENTITY, REPLICATION_CLAIM_CEILING, REPLICATION_VERSION, REQUIRED_SCENARIOS,
};
use security_alignment_os::{digest, digest_bytes, Result};
use std::fs;
use std::process::{Command, Output};
use tempfile::tempdir;

fn public_key_hex(seed: u8) -> String {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn scenarios(
    baseline: &str,
    cross_state_role: ScenarioRole,
    replacement_lock_role: ScenarioRole,
) -> Vec<ScenarioResult> {
    REQUIRED_SCENARIOS
        .iter()
        .enumerate()
        .map(|(index, scenario_id)| {
            let role = match *scenario_id {
                "cross-state-directory-lock-contention" => cross_state_role,
                "replacement-lock-ownership" => replacement_lock_role,
                _ => ScenarioRole::Primary,
            };
            let (status, recovery_status, recovery) = match *scenario_id {
                "authorized-completion" => (
                    ScenarioStatus::Applied,
                    None,
                    RecoveryDisposition::AuthorizedChangeCommitted,
                ),
                "replay-after-completion" => (
                    ScenarioStatus::Quarantined,
                    None,
                    RecoveryDisposition::AlreadyAppliedPreserved,
                ),
                "invalid-or-stale-baseline"
                | "pre-admission-expiry"
                | "pre-admission-cancellation"
                | "evaluator-requirement-substitution"
                | "path-escape"
                | "link-escape"
                | "evaluation-expiry" => (
                    ScenarioStatus::Quarantined,
                    None,
                    RecoveryDisposition::NoMutation,
                ),
                "pre-finalization-cancellation" | "pre-finalization-expiry" => (
                    ScenarioStatus::RolledBack,
                    None,
                    RecoveryDisposition::BaselineRestored,
                ),
                "crash-after-durable-intent"
                | "crash-after-replacement"
                | "completion-state-persistence-failure" => (
                    ScenarioStatus::ProcessError,
                    Some(ScenarioStatus::Frozen),
                    RecoveryDisposition::BaselineRestored,
                ),
                "concurrent-target-change" | "neighbor-change-recovery" => (
                    ScenarioStatus::Frozen,
                    None,
                    RecoveryDisposition::ExternalChangePreservedAndFrozen,
                ),
                "occupied-lock" => (
                    ScenarioStatus::ProcessError,
                    None,
                    RecoveryDisposition::NoMutation,
                ),
                "cross-state-directory-lock-contention" => match role {
                    ScenarioRole::Winner => (
                        ScenarioStatus::Applied,
                        None,
                        RecoveryDisposition::AuthorizedChangeCommitted,
                    ),
                    ScenarioRole::Contender => (
                        ScenarioStatus::Blocked,
                        None,
                        RecoveryDisposition::NoMutation,
                    ),
                    ScenarioRole::Primary => panic!("invalid cross-state role"),
                },
                "replacement-lock-ownership" => (
                    ScenarioStatus::Applied,
                    None,
                    RecoveryDisposition::AuthorizedChangeCommitted,
                ),
                "recovery-config-redirect" => (
                    ScenarioStatus::ProcessError,
                    None,
                    RecoveryDisposition::AlternateCheckoutPreserved,
                ),
                other => panic!("unhandled scenario {other}"),
            };
            let initial_checkout_digest = match *scenario_id {
                "replay-after-completion" => "b".repeat(64),
                "recovery-config-redirect" => "c".repeat(64),
                _ => baseline.to_owned(),
            };
            let final_checkout_digest = match recovery {
                RecoveryDisposition::AuthorizedChangeCommitted
                | RecoveryDisposition::AlreadyAppliedPreserved => "b".repeat(64),
                RecoveryDisposition::ExternalChangePreservedAndFrozen
                | RecoveryDisposition::AlternateCheckoutPreserved => "c".repeat(64),
                RecoveryDisposition::NoMutation | RecoveryDisposition::BaselineRestored => {
                    baseline.to_owned()
                }
            };
            ScenarioResult {
                scenario_id: (*scenario_id).into(),
                role,
                status,
                recovery_status,
                recovery,
                initial_checkout_digest,
                final_checkout_digest,
                evidence_digest: digest_bytes(format!("host-evidence-{index}").as_bytes()),
            }
        })
        .collect()
}

fn request() -> Request {
    let before_bytes = b"before  \n".to_vec();
    let after_bytes = b"before\n".to_vec();
    Request {
        request_id: "fixed-replication-request".into(),
        relative_path: "README.md".into(),
        before_digest: digest_bytes(&before_bytes),
        after_digest: digest_bytes(&after_bytes),
        before_bytes,
        after_bytes,
        checkout_baseline_digest: "a".repeat(64),
        lease_expires_at: 4_000_000_000,
        nonce: 1,
    }
}

fn baseline_manifest() -> Vec<BaselineManifestEntry> {
    vec![
        BaselineManifestEntry {
            relative_path: "README.md".into(),
            byte_length: 9,
            content_digest: digest_bytes(b"before  \n"),
            file_kind: ManifestFileKind::Regular,
            link_count: 1,
        },
        BaselineManifestEntry {
            relative_path: "neighbor.txt".into(),
            byte_length: 10,
            content_digest: digest_bytes(b"untouched\n"),
            file_kind: ManifestFileKind::Regular,
            link_count: 1,
        },
    ]
}

fn report_with_bindings(
    seed: u8,
    host_id: &str,
    operator_id: &str,
    request_digest: &str,
    baseline_manifest_digest: &str,
    cross_state_role: ScenarioRole,
    replacement_lock_role: ScenarioRole,
) -> HostReport {
    let mut report = HostReport {
        version: REPLICATION_VERSION,
        state_slice: "security-alignment-os-foundation-v1".into(),
        operation: FIXED_OPERATION_IDENTITY.into(),
        process_version: 2,
        implementation_revision: "3c19d80".to_owned() + &"0".repeat(33),
        toolchain_digest: "c".repeat(64),
        request_digest: request_digest.into(),
        checkout_baseline_digest: "a".repeat(64),
        baseline_manifest_digest: baseline_manifest_digest.into(),
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
        scenarios: scenarios(&"a".repeat(64), cross_state_role, replacement_lock_role),
        report_id: String::new(),
        host_signature: String::new(),
        operator_signature: String::new(),
    };
    report
        .sign_with_seeds([seed; 32], [seed + 10; 32])
        .expect("signed report");
    report
}

fn packet_with_reports(reports: Vec<HostReport>) -> Result<ReplicationPacket> {
    packet_for(request(), baseline_manifest(), reports)
}

fn packet_for(
    request: Request,
    baseline_manifest: Vec<BaselineManifestEntry>,
    reports: Vec<HostReport>,
) -> Result<ReplicationPacket> {
    ReplicationPacket::from_bundle(request, baseline_manifest, reports)
}

fn report(seed: u8, host_id: &str, operator_id: &str) -> HostReport {
    report_with_roles(
        seed,
        host_id,
        operator_id,
        ScenarioRole::Winner,
        ScenarioRole::Winner,
    )
}

fn report_with_roles(
    seed: u8,
    host_id: &str,
    operator_id: &str,
    cross_state_role: ScenarioRole,
    replacement_lock_role: ScenarioRole,
) -> HostReport {
    let request = request();
    let manifest = baseline_manifest();
    let request_digest = digest(&request).expect("request digest");
    let manifest_digest = baseline_manifest_digest(&manifest).expect("manifest digest");
    report_with_bindings(
        seed,
        host_id,
        operator_id,
        &request_digest,
        &manifest_digest,
        cross_state_role,
        replacement_lock_role,
    )
}

fn packet() -> ReplicationPacket {
    packet_with_reports(vec![
        report_with_roles(
            1,
            "host-a",
            "operator-a",
            ScenarioRole::Winner,
            ScenarioRole::Winner,
        ),
        report_with_roles(
            2,
            "host-b",
            "operator-b",
            ScenarioRole::Contender,
            ScenarioRole::Winner,
        ),
    ])
    .expect("packet")
}

#[test]
fn two_signed_reports_round_trip_as_canonical_packet() {
    let packet = packet();

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
    assert!(packet_with_reports(vec![first, second]).is_err());
}

#[test]
fn same_declared_operator_or_key_is_not_independent() {
    let first = report(1, "host-a", "operator-a");
    let same_operator = report(2, "host-b", "operator-a");
    assert!(packet_with_reports(vec![first.clone(), same_operator.clone()]).is_err());

    let same_key = report(1, "host-b", "operator-b");
    assert!(packet_with_reports(vec![first, same_key]).is_err());
}

#[test]
fn evidence_substitution_after_signing_is_rejected() {
    let first = report(1, "host-a", "operator-a");
    let mut second = report(2, "host-b", "operator-b");
    second.scenarios[0].evidence_digest = "e".repeat(64);
    assert!(second.validate().is_err());
    assert!(packet_with_reports(vec![first, second]).is_err());
}

#[test]
fn inconsistent_recovery_result_is_rejected() {
    let mut first = report(1, "host-a", "operator-a");
    first.scenarios[2].final_checkout_digest = "b".repeat(64);
    assert!(first.validate().is_err());
}

#[test]
fn claim_ceiling_tampering_is_rejected() {
    let mut first = report(1, "host-a", "operator-a");
    first.claim_ceiling = "unbounded maintenance authority".into();
    assert!(first.validate().is_err());
}

#[test]
fn packet_recomputes_the_fixed_transformation() {
    let mut request = request();
    request.after_bytes = b"unauthorized\n".to_vec();
    request.after_digest = digest_bytes(&request.after_bytes);
    let manifest = baseline_manifest();
    let request_digest = digest(&request).expect("request digest");
    let manifest_digest = baseline_manifest_digest(&manifest).expect("manifest digest");
    let reports = vec![
        report_with_bindings(
            1,
            "host-a",
            "operator-a",
            &request_digest,
            &manifest_digest,
            ScenarioRole::Winner,
            ScenarioRole::Winner,
        ),
        report_with_bindings(
            2,
            "host-b",
            "operator-b",
            &request_digest,
            &manifest_digest,
            ScenarioRole::Winner,
            ScenarioRole::Winner,
        ),
    ];
    assert!(packet_for(request, manifest, reports).is_err());
}

#[test]
fn request_and_manifest_bytes_are_digest_bound() {
    let mut request_tampered_packet = packet();
    request_tampered_packet.request.after_bytes = b"tampered\n".to_vec();
    assert!(request_tampered_packet.validate().is_err());

    let mut manifest_tampered_packet = packet();
    manifest_tampered_packet.baseline_manifest[0].content_digest = "e".repeat(64);
    assert!(manifest_tampered_packet.validate().is_err());
}

#[test]
fn duplicate_keys_and_noncanonical_whitespace_are_rejected() {
    let packet = packet();
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
    assert!(packet_with_reports(vec![first, second]).is_err());
}

#[test]
fn reports_must_bind_the_same_toolchain_digest() {
    let first = report(1, "host-a", "operator-a");
    let mut second = report(2, "host-b", "operator-b");
    second.toolchain_digest = "d".repeat(64);
    second
        .sign_with_seeds([2; 32], [12; 32])
        .expect("resigned report");
    assert!(packet_with_reports(vec![first, second]).is_err());
}

#[test]
fn contention_reports_bind_winner_and_contender_roles() {
    let winner = report_with_roles(
        1,
        "host-a",
        "operator-a",
        ScenarioRole::Winner,
        ScenarioRole::Winner,
    );
    let contender = report_with_roles(
        2,
        "host-b",
        "operator-b",
        ScenarioRole::Contender,
        ScenarioRole::Winner,
    );
    let packet = packet_with_reports(vec![winner, contender]).expect("role-bound packet");
    packet.validate().expect("valid role-bound packet");
    assert_eq!(
        packet.reports[1].scenarios[17].role,
        ScenarioRole::Contender
    );
}

#[test]
fn contention_requires_one_winner_and_one_contender() {
    let first = report(1, "host-a", "operator-a");
    let second = report(2, "host-b", "operator-b");
    assert!(packet_with_reports(vec![first, second]).is_err());
}

fn run_verifier(bytes: &[u8]) -> Output {
    let directory = tempdir().expect("temporary packet directory");
    let packet_path = directory.path().join("packet.json");
    fs::write(&packet_path, bytes).expect("packet bytes");
    Command::new(env!("CARGO_BIN_EXE_maintenance_replication_verifier"))
        .arg(packet_path)
        .output()
        .expect("verifier process")
}

#[test]
fn verifier_binary_accepts_only_a_valid_local_packet() {
    let packet = packet();
    let output = run_verifier(&packet.canonical_bytes().expect("canonical packet"));
    assert!(output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).expect("response");
    assert_eq!(response["status"], "valid_local_packet");
    assert_eq!(response["verdict"], "Inconclusive");
    assert_eq!(response["packet_id"], packet.packet_id);
    assert!(response.get("error").is_none());
}

#[test]
fn verifier_binary_rejects_packet_tampering_without_execution() {
    let packet = packet();
    let canonical =
        String::from_utf8(packet.canonical_bytes().expect("canonical packet")).expect("json");
    let tampered = canonical.replace(
        "normalize-trailing-ascii-spaces-v1",
        "other-maintenance-operation",
    );
    let output = run_verifier(tampered.as_bytes());
    assert!(!output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).expect("response");
    assert_eq!(response["status"], "invalid_local_packet");
    assert!(response["error"].as_str().is_some());
}
