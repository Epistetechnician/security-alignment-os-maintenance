//! Real-process broker exit-gate checks.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::broker::{
    executable_digest, BrokerClient, BrokerJournal, BrokerRequest, BrokerResponse,
    FileTransformOperation, FileTransformRequest, TransactionStatus,
};
use security_alignment_os::canonical_bytes;
use security_alignment_os::{digest_bytes, Evidence, EvidenceRegistry};
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
    let source = directory.path().join("source.txt");
    let input = b"Crash-safe broker\n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 11, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut crashed, client) = start_broker(&directory, &registry, supervisor, true);
    let result = client.request(BrokerRequest::Execute(Box::new(authorized.clone())));
    assert!(result.is_err(), "injected crash must sever IPC");
    let _ = crashed.wait();
    let journal_path = directory.path().join("journal.json");
    let journal = BrokerJournal::load(&journal_path).expect("durable journal");
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
    assert!(!directory.path().join("output-11.txt").exists());

    let (mut recovered, recovery_client) = start_broker(&directory, &registry, supervisor, false);
    let recovered_journal = BrokerJournal::load(&journal_path).expect("recovered journal");
    assert_eq!(
        recovered_journal.status(&request_digest),
        Some(TransactionStatus::Quarantined)
    );
    match recovery_client.request(BrokerRequest::Execute(Box::new(authorized))) {
        Ok(BrokerResponse::Frozen { code }) => assert_eq!(code, "broker_frozen"),
        other => panic!("unexpected recovery response: {other:?}"),
    }
    assert_eq!(fs::read(&source).expect("source read"), input);
    assert!(!directory.path().join("output-11.txt").exists());
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
        operation: FileTransformOperation::UppercaseAscii,
        source_relpath: "source.txt".into(),
        destination_relpath: format!("output-{nonce}.txt"),
        input_digest: digest_bytes(input),
        executable_digest: executable_digest(supervisor).expect("supervisor digest"),
        max_bytes: 1_000,
        max_runtime_ms: 2_000,
        requested_at: now.saturating_sub(1),
        expires_at: now + 20,
        nonce,
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

fn start_broker(
    directory: &TempDir,
    registry: &EvidenceRegistry,
    supervisor: &Path,
    kill_after_executing: bool,
) -> (Child, BrokerClient) {
    let socket = directory.path().join("broker.sock");
    let journal = directory.path().join("journal.json");
    let evidence = directory.path().join("evidence.json");
    registry.save(&evidence).expect("evidence save");
    let mut command = Command::new(env!("CARGO_BIN_EXE_capability_broker"));
    command.args([
        socket.as_os_str(),
        directory.path().as_os_str(),
        journal.as_os_str(),
        evidence.as_os_str(),
        supervisor.as_os_str(),
    ]);
    if kill_after_executing {
        command.env("BROKER_KILL_AFTER_EXECUTING", "1");
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
    let source = directory.path().join("source.txt");
    let input = b"Hello broker\n";
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
    let (mut child, client) = start_broker(&directory, &registry, supervisor, false);
    let response = client
        .request(BrokerRequest::Execute(Box::new(authorized.clone())))
        .expect("execute");
    let (receipt, hello) = match response {
        BrokerResponse::Completed { receipt, .. } => (receipt, client.hello().expect("hello")),
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(fs::read(&source).expect("source read"), input);
    assert_eq!(
        fs::read(directory.path().join("output-1.txt")).expect("output"),
        b"HELLO BROKER\n"
    );
    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    let verifier = security_alignment_os::receipts::ReceiptVerifier::with_key(
        hello.issuer_key_id,
        hello.issuer_public_key.try_into().expect("key"),
    )
    .expect("verifier");
    assert!(verifier.verify_signature(&receipt).is_ok());
    assert!(verifier.verify_signature(&forged).is_err());
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
    let source = directory.path().join("source.txt");
    let input = b"Adversarial runner\n";
    fs::write(&source, input).expect("source");
    let supervisor = Path::new(env!("CARGO_BIN_EXE_capability_supervisor"));
    let authorized = request(supervisor, input, 21, true);
    let registry = registry_for(std::slice::from_ref(&authorized));
    let (mut broker, client) = start_broker(&directory, &registry, supervisor, false);
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
