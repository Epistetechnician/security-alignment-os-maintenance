//! Real-process broker exit-gate checks.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::broker::{
    executable_digest, BrokerClient, BrokerJournal, BrokerRequest, BrokerResponse,
    FileTransformOperation, FileTransformRequest, TransactionStatus,
};
use security_alignment_os::canonical_bytes;
use security_alignment_os::receipts::ReceiptSigner;
use security_alignment_os::{digest, digest_bytes, Evidence, EvidenceRegistry};
use std::fs;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

#[test]
fn crash_recovery_freezes_in_flight_transaction_without_recreating_authority() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"Crash-safe broker\n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 11, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut crashed, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls {
            kill_after_executing: true,
            ..Default::default()
        },
    );
    let result = client.request(BrokerRequest::Execute(Box::new(authorized.clone())));
    assert!(result.is_err(), "injected crash must sever IPC");
    let _ = crashed.wait();
    let journal_path = directory.path().join("journal.json");
    let journal = BrokerJournal::load(&journal_path).expect("durable journal");
    security_alignment_os::checker::validate_broker_journal(&journal)
        .expect("independent journal check");
    let request_digest = authorized
        .to_proposal()
        .expect("proposal")
        .digest()
        .expect("digest");
    assert_eq!(
        journal.status(&request_digest),
        Some(TransactionStatus::Executing)
    );
    assert_eq!(fs::read(&source).expect("source read"), input);
    assert!(!directory.path().join("output-11.md").exists());

    let (mut recovered, recovery_client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls::default(),
    );
    let recovered_journal = BrokerJournal::load(&journal_path).expect("recovered journal");
    security_alignment_os::checker::validate_broker_journal(&recovered_journal)
        .expect("independent recovered journal check");
    assert_eq!(
        recovered_journal.status(&request_digest),
        Some(TransactionStatus::Quarantined)
    );
    match recovery_client.request(BrokerRequest::Execute(Box::new(authorized))) {
        Ok(BrokerResponse::Frozen { code }) => assert_eq!(code, "broker_frozen"),
        other => panic!("unexpected recovery response: {other:?}"),
    }
    assert_eq!(fs::read(&source).expect("source read"), input);
    assert!(!directory.path().join("output-11.md").exists());
    let _ = recovered.kill();
    let _ = recovered.wait();
}

#[test]
fn post_rename_crash_recovery_removes_uncommitted_destination() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"Post-rename crash\n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 12, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut crashed, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls {
            kill_after_rename: true,
            ..Default::default()
        },
    );
    let result = client.request(BrokerRequest::Execute(Box::new(authorized.clone())));
    assert!(result.is_err(), "injected post-rename crash must sever IPC");
    let _ = crashed.wait();
    let destination = directory.path().join("output-12.md");
    assert!(
        destination.exists(),
        "fault must occur after supervisor rename"
    );
    let journal_path = directory.path().join("journal.json");
    let request_digest = authorized
        .to_proposal()
        .expect("proposal")
        .digest()
        .expect("digest");
    let journal = BrokerJournal::load(&journal_path).expect("journal");
    security_alignment_os::checker::validate_broker_journal(&journal)
        .expect("independent in-flight journal check");
    assert_eq!(
        journal.status(&request_digest),
        Some(TransactionStatus::Executing)
    );

    let (mut recovered, recovery_client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls::default(),
    );
    let recovered_journal = BrokerJournal::load(&journal_path).expect("recovered journal");
    security_alignment_os::checker::validate_broker_journal(&recovered_journal)
        .expect("independent recovered journal check");
    assert!(
        !destination.exists(),
        "recovery must remove uncommitted output"
    );
    match recovery_client.request(BrokerRequest::Execute(Box::new(authorized))) {
        Ok(BrokerResponse::Frozen { code }) => assert_eq!(code, "broker_frozen"),
        other => panic!("unexpected recovery response: {other:?}"),
    }
    assert_eq!(fs::read(&source).expect("source"), input);
    let _ = recovered.kill();
    let _ = recovered.wait();
}

fn request(
    supervisor: &Path,
    input: &[u8],
    nonce: u64,
    telemetry_present: bool,
) -> FileTransformRequest {
    let now = timestamp();
    FileTransformRequest {
        request_id: format!("request-{nonce}"),
        agent_id: "agent-test".into(),
        subject: "tenant-test".into(),
        evidence_id: format!("evidence-{nonce}"),
        operation: FileTransformOperation::TrimTrailingAsciiSpaces,
        source_relpath: "source.md".into(),
        destination_relpath: format!("output-{nonce}.md"),
        input_digest: digest_bytes(input),
        executable_digest: executable_digest(supervisor).expect("supervisor digest"),
        max_bytes: 1_000,
        max_runtime_ms: 2_000,
        requested_at: now.saturating_sub(1),
        expires_at: now + 20,
        nonce,
        cancel_requested: false,
        telemetry_present,
    }
}

fn registry_for(requests: &[FileTransformRequest]) -> EvidenceRegistry {
    let mut registry = EvidenceRegistry::default();
    for request in requests {
        let proposal = request.to_proposal().expect("proposal");
        registry
            .insert(Evidence {
                id: request.evidence_id.clone(),
                source_digest: proposal.digest().expect("proposal digest"),
                operator_id: "operator".into(),
                validator_id: "validator".into(),
                reviewer_id: "reviewer".into(),
                valid_until: request.expires_at + 100,
                accepted: true,
                revoked: false,
            })
            .expect("evidence");
    }
    registry
}

#[derive(Clone, Copy, Default)]
struct BrokerTestControls {
    kill_after_executing: bool,
    kill_after_rename: bool,
    cancel_after_rename: bool,
    cancel_after_evaluation: bool,
    cancel_before_replacement: bool,
}

fn start_broker(
    directory: &TempDir,
    registry: &EvidenceRegistry,
    supervisor: &Path,
    controls: BrokerTestControls,
) -> (Child, BrokerClient) {
    let socket = directory.path().join("broker.sock");
    let journal = directory.path().join("journal.json");
    let evidence = directory.path().join("evidence.json");
    let seed_path = directory.path().join("broker.seed");
    fs::write(&seed_path, [7u8; 32]).expect("seed");
    #[cfg(unix)]
    fs::set_permissions(
        &seed_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("seed permissions");
    registry.save(&evidence).expect("evidence save");
    let mut command = Command::new(env!("CARGO_BIN_EXE_capability_broker"));
    command.args([
        socket.as_os_str(),
        directory.path().as_os_str(),
        journal.as_os_str(),
        evidence.as_os_str(),
        supervisor.as_os_str(),
        seed_path.as_os_str(),
    ]);
    if controls.kill_after_executing {
        command.env("BROKER_KILL_AFTER_EXECUTING", "1");
    }
    if controls.kill_after_rename {
        command.env("BROKER_KILL_AFTER_RENAME", "1");
    }
    if controls.cancel_after_rename {
        command.env("BROKER_CANCEL_AFTER_RENAME", "1");
    }
    if controls.cancel_after_evaluation {
        command.env("BROKER_CANCEL_AFTER_EVALUATION", "1");
    }
    if controls.cancel_before_replacement {
        command.env("BROKER_CANCEL_BEFORE_REPLACEMENT", "1");
    }
    let child = command.spawn().expect("broker spawn");
    let client = BrokerClient::new(socket);
    for _ in 0..200 {
        if client.hello().is_ok() {
            return (child, client);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("broker did not accept IPC hello");
}

#[test]
fn broker_process_commits_authorized_transform_and_rejects_replay() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"Hello broker  \n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 1, true);
    let escaped = FileTransformRequest {
        destination_relpath: "../escape.txt".into(),
        nonce: 2,
        request_id: "request-2".into(),
        evidence_id: "evidence-2".into(),
        ..authorized.clone()
    };
    let missing_telemetry = FileTransformRequest {
        nonce: 3,
        request_id: "request-3".into(),
        evidence_id: "evidence-3".into(),
        telemetry_present: false,
        ..authorized.clone()
    };
    let registry = registry_for(&[
        authorized.clone(),
        escaped.clone(),
        missing_telemetry.clone(),
    ]);
    let (mut child, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls::default(),
    );
    let response = client
        .request(BrokerRequest::Execute(Box::new(authorized.clone())))
        .expect("execute");
    let (receipt, execution_receipt, decision_digest, decision, policy, hello) =
        match response.clone() {
            BrokerResponse::Completed {
                receipt,
                execution_receipt,
                decision_digest,
                decision,
                policy,
                ..
            } => (
                receipt,
                execution_receipt,
                decision_digest,
                decision,
                policy,
                client.hello().expect("hello"),
            ),
            other => panic!("unexpected response: {other:?}"),
        };
    assert_eq!(fs::read(&source).expect("source read"), input);
    assert_eq!(
        fs::read(directory.path().join("output-1.md")).expect("output"),
        b"Hello broker\n"
    );
    let committed_journal =
        BrokerJournal::load(&directory.path().join("journal.json")).expect("committed journal");
    security_alignment_os::checker::validate_broker_journal(&committed_journal)
        .expect("independent committed journal check");
    let mut tampered_journal = committed_journal.clone();
    tampered_journal.entries[1].agent_id.push_str("-tampered");
    for index in 0..tampered_journal.entries.len() {
        let previous_digest = if index == 0 {
            "0".repeat(64)
        } else {
            tampered_journal.entries[index - 1].entry_digest.clone()
        };
        let event = &mut tampered_journal.entries[index];
        event.previous_digest = previous_digest;
        let material = (
            event.sequence,
            event.previous_digest.clone(),
            event.request_digest.clone(),
            event.agent_id.clone(),
            event.nonce,
            event.destination_relpath.clone(),
            event.decision_digest.clone(),
            event.capability_token_id.clone(),
            event.status,
            event.output_digest.clone(),
        );
        event.entry_digest = digest(&material).expect("tampered event digest");
    }
    assert!(tampered_journal.validate().is_err());
    assert!(security_alignment_os::checker::validate_broker_journal(&tampered_journal).is_err());
    assert_eq!(
        committed_journal.status(
            &authorized
                .to_proposal()
                .expect("proposal")
                .digest()
                .expect("digest")
        ),
        Some(TransactionStatus::Committed)
    );
    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    let public_key: [u8; 32] = hello.issuer_public_key.clone().try_into().expect("key");
    let mut verifier =
        security_alignment_os::receipts::ReceiptVerifier::with_key(hello.issuer_key_id, public_key)
            .expect("verifier");
    assert!(verifier.verify_signature(&receipt).is_ok());
    assert!(verifier.verify_signature(&forged).is_err());
    verifier
        .verify_execution(
            &execution_receipt,
            &receipt,
            "evidence-1",
            &registry
                .record_digest("evidence-1")
                .expect("evidence digest"),
            &authorized.input_digest,
            security_alignment_os::broker::TRANSFORMER_ID,
            &decision_digest,
            timestamp(),
        )
        .expect("execution receipt");
    security_alignment_os::checker::validate_capability_receipt(
        &receipt,
        "tenant-test",
        &authorized.to_proposal().expect("proposal"),
        &decision,
        &policy,
        public_key,
        timestamp(),
    )
    .expect("independent capability receipt");
    security_alignment_os::checker::validate_execution_receipt(
        &execution_receipt,
        &receipt,
        "evidence-1",
        &registry
            .record_digest("evidence-1")
            .expect("evidence digest"),
        &authorized.input_digest,
        security_alignment_os::broker::TRANSFORMER_ID,
        &decision_digest,
        timestamp(),
        public_key,
    )
    .expect("independent execution receipt");
    let expected_signer =
        ReceiptSigner::from_seed("broker-ephemeral-v1", [7; 32]).expect("seed signer");
    let trust = security_alignment_os::integration::BrokerTrustAnchor {
        issuer_key_id: expected_signer.key_id().into(),
        issuer_public_key: expected_signer.verifying_key_bytes(),
    };
    let accepted = security_alignment_os::integration::accept_broker_completion(
        &authorized,
        &response,
        &registry,
        &trust,
        directory.path(),
        timestamp(),
    )
    .expect("broker completion acceptance");
    assert_eq!(accepted.request_digest, decision.candidate_digest);
    assert_eq!(accepted.output_digest, digest_bytes(b"Hello broker\n"));
    let forged_output = match response.clone() {
        BrokerResponse::Completed {
            request_digest,
            decision_digest,
            decision,
            policy,
            receipt,
            execution_receipt,
            ..
        } => BrokerResponse::Completed {
            request_digest,
            decision_digest,
            decision,
            policy,
            receipt,
            execution_receipt,
            output_digest: "0".repeat(64),
        },
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(
        security_alignment_os::integration::accept_broker_completion(
            &authorized,
            &forged_output,
            &registry,
            &trust,
            directory.path(),
            timestamp(),
        )
        .is_err()
    );
    let wrong_trust = security_alignment_os::integration::BrokerTrustAnchor {
        issuer_key_id: "wrong-broker-key".into(),
        issuer_public_key: [3; 32],
    };
    assert!(
        security_alignment_os::integration::accept_broker_completion(
            &authorized,
            &response,
            &registry,
            &wrong_trust,
            directory.path(),
            timestamp(),
        )
        .is_err()
    );
    let mut revoked_registry = registry.clone();
    revoked_registry
        .revoke("evidence-1")
        .expect("revoke evidence");
    assert!(
        security_alignment_os::integration::accept_broker_completion(
            &authorized,
            &response,
            &revoked_registry,
            &trust,
            directory.path(),
            timestamp(),
        )
        .is_err()
    );
    match client.request(BrokerRequest::Execute(Box::new(authorized))) {
        Ok(BrokerResponse::Rejected { code, .. }) => assert_eq!(code, "replay"),
        other => panic!("unexpected replay response: {other:?}"),
    }
    match client.request(BrokerRequest::Execute(Box::new(escaped))) {
        Ok(BrokerResponse::Rejected { code, .. }) => assert_eq!(code, "invalid_request"),
        other => panic!("unexpected escape response: {other:?}"),
    }
    assert_eq!(fs::read(&source).expect("source read"), input);
    match client.request(BrokerRequest::Execute(Box::new(missing_telemetry))) {
        Ok(BrokerResponse::Quarantined { code, .. }) => assert_eq!(code, "telemetry_missing"),
        other => panic!("unexpected telemetry response: {other:?}"),
    }
    match client.request(BrokerRequest::Execute(Box::new(request(
        supervisor, input, 4, true,
    )))) {
        Ok(BrokerResponse::Frozen { code }) => assert_eq!(code, "broker_frozen"),
        other => panic!("unexpected frozen response: {other:?}"),
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn adversarial_runner_contains_direct_and_malformed_attempts() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"Adversarial runner\n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 21, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut broker, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls::default(),
    );
    let request_path = directory.path().join("request.json");
    fs::write(
        &request_path,
        canonical_bytes(&authorized).expect("request encoding"),
    )
    .expect("request file");
    let status = Command::new(env!("CARGO_BIN_EXE_broker_adversarial_runner"))
        .args([
            client.socket_path().as_os_str(),
            request_path.as_os_str(),
            directory.path().as_os_str(),
            supervisor.as_os_str(),
        ])
        .status()
        .expect("runner spawn");
    assert!(status.success());
    assert_eq!(fs::read(&source).expect("source read"), input);
    let _ = broker.kill();
    let _ = broker.wait();
}

#[test]
fn cancellation_before_admission_preserves_workspace() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"cancel before  \n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let mut cancelled = request(supervisor, input, 31, true);
    cancelled.cancel_requested = true;
    let registry = registry_for(std::slice::from_ref(&cancelled));
    let (mut broker, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls::default(),
    );
    match client.request(BrokerRequest::Execute(Box::new(cancelled))) {
        Ok(BrokerResponse::Rejected { code, .. }) => {
            assert_eq!(code, "cancelled_before_admission")
        }
        other => panic!("unexpected cancellation response: {other:?}"),
    }
    assert_eq!(fs::read(&source).expect("source"), input);
    assert!(!directory.path().join("output-31.md").exists());
    let _ = broker.kill();
    let _ = broker.wait();
}

#[test]
fn cancellation_after_replacement_rolls_back_and_freezes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"cancel after  \n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 32, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut broker, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls {
            cancel_after_rename: true,
            ..Default::default()
        },
    );
    match client.request(BrokerRequest::Execute(Box::new(authorized.clone()))) {
        Ok(BrokerResponse::Quarantined { code, .. }) => {
            assert_eq!(code, "cancelled_after_replacement")
        }
        other => panic!("unexpected cancellation response: {other:?}"),
    }
    let journal = BrokerJournal::load(&directory.path().join("journal.json")).expect("journal");
    let request_digest = authorized
        .to_proposal()
        .expect("proposal")
        .digest()
        .expect("digest");
    assert_eq!(
        journal.status(&request_digest),
        Some(TransactionStatus::RolledBack)
    );
    assert_eq!(fs::read(&source).expect("source"), input);
    assert!(!directory.path().join("output-32.md").exists());
    match client.request(BrokerRequest::Execute(Box::new(authorized))) {
        Ok(BrokerResponse::Frozen { code }) => assert_eq!(code, "broker_frozen"),
        other => panic!("unexpected frozen response: {other:?}"),
    }
    let _ = broker.kill();
    let _ = broker.wait();
}

fn assert_cancellation_checkpoint(
    cancel_after_evaluation: bool,
    cancel_before_replacement: bool,
    nonce: u64,
) {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"cancel checkpoint  \n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, nonce, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut broker, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls {
            cancel_after_evaluation,
            cancel_before_replacement,
            ..Default::default()
        },
    );
    match client.request(BrokerRequest::Execute(Box::new(authorized.clone()))) {
        Ok(BrokerResponse::Quarantined { code, .. }) => {
            assert!(
                code.starts_with("supervisor_failed_1_"),
                "unexpected code: {code}"
            );
        }
        other => panic!("unexpected cancellation response: {other:?}"),
    }
    let journal = BrokerJournal::load(&directory.path().join("journal.json")).expect("journal");
    let request_digest = authorized
        .to_proposal()
        .expect("proposal")
        .digest()
        .expect("digest");
    assert_eq!(
        journal.status(&request_digest),
        Some(TransactionStatus::RolledBack)
    );
    assert_eq!(fs::read(&source).expect("source"), input);
    assert!(!directory.path().join(format!("output-{nonce}.md")).exists());
    let _ = broker.kill();
    let _ = broker.wait();
}

#[test]
fn cancellation_checkpoints_before_replacement_preserve_workspace() {
    assert_cancellation_checkpoint(true, false, 33);
    assert_cancellation_checkpoint(false, true, 34);
}

#[test]
fn occupied_broker_socket_rejects_a_second_writer() {
    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join("source.md");
    let input = b"occupied socket\n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 35, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut broker, client) = start_broker(
        &directory,
        &registry,
        supervisor,
        BrokerTestControls::default(),
    );
    let status = Command::new(env!("CARGO_BIN_EXE_capability_broker"))
        .args([
            client.socket_path().as_os_str(),
            directory.path().as_os_str(),
            directory.path().join("journal.json").as_os_str(),
            directory.path().join("evidence.json").as_os_str(),
            supervisor.as_os_str(),
            directory.path().join("broker.seed").as_os_str(),
        ])
        .status()
        .expect("second broker spawn");
    assert_eq!(status.code(), Some(2));
    let _ = broker.kill();
    let _ = broker.wait();
}
