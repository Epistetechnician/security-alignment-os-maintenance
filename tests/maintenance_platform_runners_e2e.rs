//! End-to-end tests for the shared local workloads behind the platform runners.
//!
//! State slices: `security-alignment-os-foundation-v1` and
//! `maintenance-platform-runner-hermetic-e2e-v1`.

#[allow(dead_code)]
#[path = "../src/bin/maintenance_confidential_space_runner.rs"]
mod confidential_space_runner;
#[allow(dead_code)]
#[path = "../src/bin/maintenance_nitro_enclave_runner.rs"]
mod nitro_enclave_runner;

use security_alignment_os::maintenance_replication::REPLICATION_CLAIM_CEILING;
use security_alignment_os::{canonical_bytes, digest_bytes};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use tempfile::tempdir;

const IMPLEMENTATION_REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE_TREE_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn private_local_binaries(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = root.join("tools");
    std::fs::create_dir(&bin_dir).expect("private local binary directory");
    std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restrict local binary directory");
    let copy = |name: &str, source: &str| {
        let destination = bin_dir.join(name);
        std::fs::copy(source, &destination).expect("copy local executable into private custody");
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
            .expect("restrict local executable");
        destination
    };
    (
        copy(
            "maintenance_replication_runner",
            env!("CARGO_BIN_EXE_maintenance_replication_runner"),
        ),
        copy(
            "maintenance_broker",
            env!("CARGO_BIN_EXE_maintenance_broker"),
        ),
        copy(
            "maintenance_evaluator",
            env!("CARGO_BIN_EXE_maintenance_evaluator"),
        ),
    )
}

fn assert_full_report(report: &Value) {
    assert_eq!(report["scenarios"].as_array().unwrap().len(), 20);
    assert_eq!(report["claim_ceiling"], REPLICATION_CLAIM_CEILING);
}

fn read_http_request(stream: &mut UnixStream) -> (String, Vec<u8>) {
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("attestation request header");
        header.push(byte[0]);
        assert!(header.len() <= 16 * 1024, "request headers bounded");
    }
    let header_text = std::str::from_utf8(&header).expect("UTF-8 HTTP headers");
    let content_length = header_text
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content length"))
        })
        .expect("content length present");
    assert!(content_length <= 4096, "request body bounded");
    let mut body = vec![0; content_length];
    stream
        .read_exact(&mut body)
        .expect("attestation request body");
    (header_text.to_owned(), body)
}

fn synthetic_attestation_server(socket_path: &Path) -> thread::JoinHandle<Value> {
    let listener = UnixListener::bind(socket_path).expect("bind synthetic attestation socket");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept workload request");
        let (headers, body) = read_http_request(&mut stream);
        assert!(headers.starts_with("POST /v1/token HTTP/1.1\r\n"));
        let request: Value = serde_json::from_slice(&body).expect("attestation JSON request");
        assert_eq!(request["token_type"], "OIDC");
        assert_eq!(request["audience"], "https://local.invalid/test-audience");
        let nonce = request["nonces"][0].as_str().expect("nonce");
        assert_eq!(nonce.len(), 64 + 1 + 48);
        assert!(nonce.as_bytes()[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
        assert_eq!(nonce.as_bytes()[64], b':');
        assert!(nonce.as_bytes()[65..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));

        let response_body = br#"{"token":"synthetic-gcp-token"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        )
        .expect("write synthetic HTTP response headers");
        stream
            .write_all(response_body)
            .expect("write synthetic HTTP response body");
        stream
            .shutdown(Shutdown::Write)
            .expect("close response body");
        request
    })
}

#[test]
fn confidential_space_workload_runs_real_local_matrix_and_binds_synthetic_token() {
    let temp = tempdir().expect("temporary workload root");
    let socket_path = temp.path().join("attestation.sock");
    let server = synthetic_attestation_server(&socket_path);
    let (runner, broker, evaluator) = private_local_binaries(temp.path());

    let envelope_bytes = confidential_space_runner::run_workload(
        &temp.path().join("workload"),
        &runner,
        &broker,
        &evaluator,
        &socket_path,
        IMPLEMENTATION_REVISION,
        "https://local.invalid/test-audience",
    )
    .expect("Confidential Space workload completes locally");
    let request = server.join().expect("synthetic server completes");
    let envelope: Value = serde_json::from_slice(&envelope_bytes).expect("canonical envelope");
    let report_bytes = std::fs::read(temp.path().join("workload/artifacts/report.json"))
        .expect("canonical report retained in test custody");
    let report: Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    let report_digest = digest_bytes(&report_bytes);

    assert_full_report(&report);
    assert_eq!(envelope["report"], report);
    assert_eq!(envelope["report_digest"], report_digest);
    assert_eq!(envelope["attestation_token"], "synthetic-gcp-token");
    assert_eq!(envelope["attestation_audience"], request["audience"]);
    assert!(envelope["attestation_nonce"]
        .as_str()
        .unwrap()
        .starts_with(&format!("{report_digest}:")));
    assert_eq!(
        envelope["claim_ceiling"],
        "MachineAttestedReproduction; not IndependentReplication"
    );
}

#[test]
fn nitro_workload_runs_real_local_matrix_and_binds_synthetic_attestation() {
    let temp = tempdir().expect("temporary workload root");
    let (runner, broker, evaluator) = private_local_binaries(temp.path());
    let nonce = "ab".repeat(32);
    let expected_nonce = nonce.clone();
    let attestation_document = b"synthetic-nsm-document".to_vec();
    let expected_document = attestation_document.clone();
    let quoted_user_data = std::cell::RefCell::new(String::new());
    let quoted_user_data_out = &quoted_user_data;

    let envelope_bytes = nitro_enclave_runner::run_workload(
        nitro_enclave_runner::WorkloadConfig {
            root: &temp.path().join("workload"),
            runner: &runner,
            broker: &broker,
            evaluator: &evaluator,
            implementation_revision: IMPLEMENTATION_REVISION,
            source_tree_sha256: SOURCE_TREE_SHA256,
            nonce: &nonce,
            audience: "aws-nitro-enclaves://local-test",
        },
        move |user_data, attestation_nonce| {
            assert_eq!(attestation_nonce, expected_nonce.as_bytes());
            assert_eq!(user_data.len(), 64);
            assert!(user_data
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
            *quoted_user_data_out.borrow_mut() = String::from_utf8(user_data.to_vec()).unwrap();
            Ok(expected_document)
        },
    )
    .expect("Nitro workload completes locally");
    let envelope: Value = serde_json::from_slice(&envelope_bytes).expect("canonical envelope");
    let report_bytes = std::fs::read(temp.path().join("workload/artifacts/report.json"))
        .expect("canonical report retained in test custody");
    let report: Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    let report_digest = digest_bytes(&report_bytes);
    let expected_user_data = digest_bytes(
        &canonical_bytes(&serde_json::json!({
            "implementation_revision": IMPLEMENTATION_REVISION,
            "report_digest": report_digest,
            "source_tree_sha256": SOURCE_TREE_SHA256,
        }))
        .unwrap(),
    );
    let changed_revision_user_data = digest_bytes(
        &canonical_bytes(&serde_json::json!({
            "implementation_revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "report_digest": report_digest,
            "source_tree_sha256": SOURCE_TREE_SHA256,
        }))
        .unwrap(),
    );

    assert_full_report(&report);
    assert_eq!(envelope["report"], report);
    assert_eq!(envelope["report_digest"], report_digest);
    assert_eq!(envelope["implementation_revision"], IMPLEMENTATION_REVISION);
    assert_eq!(report["implementation_revision"], IMPLEMENTATION_REVISION);
    assert_eq!(envelope["source_tree_sha256"], SOURCE_TREE_SHA256);
    assert_eq!(envelope["attestation_user_data"], expected_user_data);
    assert_ne!(expected_user_data, changed_revision_user_data);
    assert_eq!(quoted_user_data.into_inner(), expected_user_data);
    assert_eq!(envelope["attestation_nonce"], nonce);
    assert_eq!(
        envelope["attestation_document_hex"],
        "73796e7468657469632d6e736d2d646f63756d656e74"
    );
    assert_eq!(
        envelope["attestation_document_digest"],
        digest_bytes(b"synthetic-nsm-document")
    );
    assert_eq!(
        envelope["claim_ceiling"],
        "MachineAttestedReproduction; not IndependentReplication"
    );
}
