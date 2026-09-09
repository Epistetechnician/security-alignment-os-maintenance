//! Machine-attested fixed-operation runner for Google Confidential Space.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This workload requests a Google Cloud Attestation OIDC token, runs the
//! existing 20-scenario maintenance replication runner, and emits one compact
//! JSON envelope. It does not claim independent operator custody or convert
//! a Linux result into the existing macOS two-host packet.

use security_alignment_os::{canonical_bytes, digest_bytes, Error, Result, STATE_SLICE};
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

// Confidential Space production workloads run with a read-only image root.
// Keep only the attestation socket under `/run`; all operation state belongs
// in the writable ephemeral filesystem.
const ROOT: &str = "/tmp/maintenance";
const CHECKOUT: &str = "/tmp/maintenance/checkout";
const KEYS: &str = "/tmp/maintenance/keys";
const ARTIFACTS: &str = "/tmp/maintenance/artifacts";
const ATTESTATION_SOCKET: &str = "/run/container_launcher/teeserver.sock";
const DEFAULT_AUDIENCE: &str = "https://security-alignment-os.example/machine-attestation/v1";

#[derive(Serialize)]
struct TokenRequest<'a> {
    audience: &'a str,
    token_type: &'a str,
    nonces: [&'a str; 1],
}

#[derive(Serialize)]
struct WorkloadEnvelope {
    state_slice: &'static str,
    status: &'static str,
    claim_ceiling: &'static str,
    attestation_issuer: &'static str,
    attestation_audience: String,
    attestation_nonce: String,
    attestation_token: String,
    report_digest: String,
    report: Value,
}

fn rejected(message: impl Into<String>) -> Error {
    Error::Rejected(message.into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_nonce() -> Result<String> {
    let mut bytes = [0_u8; 24];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

fn request_attestation(audience: &str, nonce: &str) -> Result<String> {
    let body = serde_json::to_vec(&TokenRequest {
        audience,
        token_type: "OIDC",
        nonces: [nonce],
    })?;
    let mut stream = UnixStream::connect(ATTESTATION_SOCKET)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| rejected("attestation response has no HTTP header boundary"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| rejected("attestation response headers are not UTF-8"))?;
    if !headers.starts_with("HTTP/1.1 200 ") && !headers.starts_with("HTTP/1.0 200 ") {
        return Err(rejected(format!("attestation request failed: {headers}")));
    }
    let body = &response[header_end + 4..];
    let body_text = std::str::from_utf8(body)
        .map_err(|_| rejected("attestation response body is not UTF-8"))?
        .trim();
    if body_text.is_empty() {
        return Err(rejected("attestation response body is empty"));
    }
    if let Ok(value) = serde_json::from_str::<Value>(body_text) {
        if let Some(token) = value.as_str() {
            return Ok(token.to_owned());
        }
        if let Some(token) = value.get("token").and_then(Value::as_str) {
            return Ok(token.to_owned());
        }
    }
    Ok(body_text.to_owned())
}

fn run(binary: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new(binary).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(rejected(format!(
        "{} failed: {}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_checkout() -> Result<()> {
    fs::create_dir_all(CHECKOUT)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(CHECKOUT, fs::Permissions::from_mode(0o700))?;
    }
    write_private(
        &PathBuf::from(CHECKOUT).join("README.md"),
        b"# Replication  \nDocumentation.   \n",
    )?;
    write_private(
        &PathBuf::from(CHECKOUT).join("neighbor.txt"),
        b"untouched\n",
    )?;
    Ok(())
}

fn main() {
    let result: Result<()> = (|| {
        let implementation_revision = std::env::var("IMPLEMENTATION_REVISION")
            .map_err(|_| rejected("IMPLEMENTATION_REVISION is required"))?;
        let audience =
            std::env::var("ATTESTATION_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_owned());
        let nonce = random_nonce()?;
        let token = request_attestation(&audience, &nonce)?;

        fs::create_dir_all(ROOT)?;
        fs::create_dir_all(KEYS)?;
        fs::create_dir_all(ARTIFACTS)?;
        create_checkout()?;

        let runner = Path::new("/opt/maintenance/bin/maintenance_replication_runner");
        let broker = Path::new("/opt/maintenance/bin/maintenance_broker");
        let evaluator = Path::new("/opt/maintenance/bin/maintenance_evaluator");
        let bundle = Path::new(ROOT).join("frozen-bundle.json");
        let spec = Path::new(ROOT).join("runner-spec.json");
        run(runner, &["keygen", KEYS])?;
        run(
            runner,
            &[
                "freeze",
                CHECKOUT,
                bundle
                    .to_str()
                    .ok_or_else(|| rejected("bundle path is invalid"))?,
                "maintenance-replication-v1",
                "4102444800",
                "1",
            ],
        )?;
        run(
            runner,
            &[
                "init",
                CHECKOUT,
                ARTIFACTS,
                broker
                    .to_str()
                    .ok_or_else(|| rejected("broker path is invalid"))?,
                evaluator
                    .to_str()
                    .ok_or_else(|| rejected("evaluator path is invalid"))?,
                &format!("{KEYS}/evaluator.seed"),
                "gcp-confidential-space",
                "machine-attested-runner",
                &format!("{KEYS}/host.seed"),
                &format!("{KEYS}/operator.seed"),
                &implementation_revision,
                "4102444800",
                "1",
                "winner",
                spec.to_str()
                    .ok_or_else(|| rejected("spec path is invalid"))?,
            ],
        )?;
        run(
            runner,
            &[
                "report",
                spec.to_str()
                    .ok_or_else(|| rejected("spec path is invalid"))?,
            ],
        )?;
        let report_path = Path::new(ARTIFACTS).join("report.json");
        let report_bytes = fs::read(&report_path)?;
        let report: Value = serde_json::from_slice(&report_bytes)?;
        let envelope = WorkloadEnvelope {
            state_slice: STATE_SLICE,
            status: "machine_attested_report",
            claim_ceiling: "MachineAttestedReproduction; not IndependentReplication",
            attestation_issuer: "https://confidentialcomputing.googleapis.com",
            attestation_audience: audience,
            attestation_nonce: nonce,
            attestation_token: token,
            report_digest: digest_bytes(&report_bytes),
            report,
        };
        let output = canonical_bytes(&envelope)?;
        let output = String::from_utf8(output)
            .map_err(|_| rejected("attested workload envelope is not UTF-8"))?;
        println!("{output}");
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("machine-attested maintenance runner error: {error}");
        std::process::exit(1);
    }
}
