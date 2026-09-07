//! Separate hostile-client runner for the broker boundary.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! The runner never receives a broker signing key and records only compact
//! pass/fail observations. It exercises direct supervisor invocation, path
//! escape, receipt forgery, replay, malformed child-operation input, and
//! missing telemetry containment.

use security_alignment_os::broker::{
    BrokerClient, BrokerRequest, BrokerResponse, FileTransformRequest, SupervisorJob,
    MAX_FRAME_BYTES,
};
use security_alignment_os::receipts::ReceiptVerifier;
use security_alignment_os::{canonical_bytes, digest_bytes};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

fn fail() -> ! {
    std::process::exit(1)
}

fn expect_invalid_path(client: &BrokerClient, request: &FileTransformRequest) -> bool {
    let mut value = request.clone();
    value.request_id.push_str("-path");
    value.evidence_id.push_str("-path");
    value.nonce = value.nonce.saturating_add(1);
    value.destination_relpath = "../broker-escape.txt".into();
    matches!(
        client.request(BrokerRequest::Execute(Box::new(value))),
        Ok(BrokerResponse::Rejected { code, .. }) if code == "invalid_request"
    )
}

fn expect_direct_supervisor_rejected(
    request: &FileTransformRequest,
    workspace: &Path,
    supervisor: &Path,
) -> bool {
    let input = match fs::read(workspace.join(&request.source_relpath)) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let output: Vec<u8> = input.iter().map(|byte| byte.to_ascii_uppercase()).collect();
    let workspace = match fs::canonicalize(workspace) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let job = SupervisorJob {
        request: request.clone(),
        workspace: workspace.clone(),
        expected_output_digest: digest_bytes(&output),
        launch_token_digest: "0".repeat(64),
    };
    let path = workspace.join(".adversarial-direct-job.json");
    let bytes = match canonical_bytes(&job) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if file.write_all(&bytes).is_err() || file.sync_all().is_err() {
        let _ = fs::remove_file(&path);
        return false;
    }
    drop(file);
    let result = Command::new(supervisor)
        .args(["--job", path.to_str().unwrap_or("")])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = fs::remove_file(&path);
    result.is_ok_and(|status| !status.success())
        && !workspace.join(&request.destination_relpath).exists()
}

#[cfg(unix)]
fn expect_malformed_child_operation(client: &BrokerClient) -> bool {
    let Ok(mut stream) = UnixStream::connect(client.socket_path()) else {
        return false;
    };
    let malformed = br#"{"Execute":{"request_id":"child","operation":"SpawnChild"}}"#;
    if stream.write_all(malformed).is_err() || stream.write_all(b"\n").is_err() {
        return false;
    }
    let mut response = String::new();
    let _ = BufReader::new(stream).read_line(&mut response);
    response.len() <= MAX_FRAME_BYTES
}

#[cfg(not(unix))]
fn expect_malformed_child_operation(_client: &BrokerClient) -> bool {
    false
}

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(socket) = args.next() else { fail() };
    let Some(request_path) = args.next() else {
        fail()
    };
    let Some(workspace) = args.next() else { fail() };
    let Some(supervisor) = args.next() else {
        fail()
    };
    if args.next().is_some() {
        fail();
    }
    let request: FileTransformRequest = match fs::read(&request_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => fail(),
    };
    let client = BrokerClient::new(PathBuf::from(socket));
    let hello = match client.hello() {
        Ok(value) => value,
        Err(_) => fail(),
    };
    let direct =
        expect_direct_supervisor_rejected(&request, Path::new(&workspace), Path::new(&supervisor));
    let path_escape = expect_invalid_path(&client, &request);
    let first = match client.request(BrokerRequest::Execute(Box::new(request.clone()))) {
        Ok(value) => value,
        Err(_) => fail(),
    };
    let (replay, forged_receipt) = match first {
        BrokerResponse::Completed { receipt, .. } => {
            let mut forged = receipt.clone();
            forged.signature[0] ^= 1;
            let verifier = ReceiptVerifier::with_key(
                hello.issuer_key_id,
                match hello.issuer_public_key.try_into() {
                    Ok(value) => value,
                    Err(_) => fail(),
                },
            )
            .unwrap_or_else(|_| fail());
            let forged_rejected = verifier.verify_signature(&forged).is_err();
            let replay = matches!(
                client.request(BrokerRequest::Execute(Box::new(request.clone()))),
                Ok(BrokerResponse::Rejected { code, .. }) if code == "replay"
            );
            (replay, forged_rejected)
        }
        BrokerResponse::Rejected { code, .. } if code == "replay" => (true, true),
        _ => fail(),
    };
    let mut telemetry = request;
    telemetry.request_id.push_str("-telemetry");
    telemetry.evidence_id.push_str("-telemetry");
    telemetry.nonce = telemetry.nonce.saturating_add(2);
    telemetry.telemetry_present = false;
    let telemetry_frozen = matches!(
        client.request(BrokerRequest::Execute(Box::new(telemetry))),
        Ok(BrokerResponse::Quarantined { code, .. }) if code == "telemetry_missing"
    );
    let child_input = expect_malformed_child_operation(&client);
    let summary = serde_json::json!({
        "direct_supervisor_rejected": direct,
        "path_escape_rejected": path_escape,
        "replay_rejected": replay,
        "forged_receipt_rejected": forged_receipt,
        "missing_telemetry_froze": telemetry_frozen,
        "malformed_child_operation_contained": child_input,
    });
    println!(
        "{}",
        serde_json::to_string(&summary).unwrap_or_else(|_| "{}".into())
    );
    if !direct || !path_escape || !replay || !forged_receipt || !telemetry_frozen || !child_input {
        fail();
    }
}
