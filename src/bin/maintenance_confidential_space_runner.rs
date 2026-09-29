//! Machine-attested fixed-operation runner for Google Confidential Space.
//!
//! State slices: `security-alignment-os-foundation-v1` and
//! `maintenance-platform-runner-hermetic-e2e-v1`.
//!
//! This workload requests a Google Cloud Attestation OIDC token, runs the
//! existing 20-scenario maintenance replication runner, and emits one compact
//! JSON envelope. It does not claim independent operator custody or convert
//! a Linux result into the existing macOS two-host packet.

use security_alignment_os::maintenance_replication::HostReport;
use security_alignment_os::{canonical_bytes, digest_bytes, Error, Result, STATE_SLICE};
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

// Confidential Space production workloads run with a read-only image root.
// Keep only the attestation socket under `/run`; all operation state belongs
// in the writable ephemeral filesystem.
const ROOT: &str = "/tmp/maintenance";
const ATTESTATION_SOCKET: &str = "/run/container_launcher/teeserver.sock";
const DEFAULT_AUDIENCE: &str = "https://security-alignment-os.example/machine-attestation/v1";
const MAX_ATTESTATION_RESPONSE_BYTES: u64 = 1024 * 1024;

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
    report: HostReport,
}

fn rejected(message: impl Into<String>) -> Error {
    Error::Rejected(message.into())
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut cursor = 0;
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| rejected("attestation chunk has no size boundary"))?
            + cursor;
        let size_text = std::str::from_utf8(&body[cursor..line_end])
            .map_err(|_| rejected("attestation chunk size is not UTF-8"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| rejected("attestation chunk size is not hexadecimal"))?;
        cursor = line_end + 2;
        if size == 0 {
            let trailers = &body[cursor..];
            if trailers == b"\r\n" {
                return Ok(decoded);
            }
            let trailer_end = trailers
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .ok_or_else(|| rejected("attestation trailers have no final boundary"))?;
            if trailer_end + 4 != trailers.len() {
                return Err(rejected(
                    "attestation response has bytes after its final chunk",
                ));
            }
            let fields = &trailers[..trailer_end];
            if fields.is_empty()
                || fields.split(|byte| *byte == b'\n').any(|line| {
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    !line.contains(&b':') || line.iter().any(|byte| byte.is_ascii_control())
                })
            {
                return Err(rejected("attestation trailers are malformed"));
            }
            return Ok(decoded);
        }
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| rejected("attestation chunk size overflows"))?;
        let terminator_end = end
            .checked_add(2)
            .ok_or_else(|| rejected("attestation chunk size overflows"))?;
        if terminator_end > body.len() || &body[end..terminator_end] != b"\r\n" {
            return Err(rejected("attestation chunk has an invalid terminator"));
        }
        decoded.extend_from_slice(&body[cursor..end]);
        cursor = end + 2;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_nonce() -> Result<String> {
    let mut bytes = [0_u8; 24];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

fn report_bound_nonce(report_digest: &str, challenge: &str) -> Result<String> {
    let is_lower_hex = |value: &str| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if report_digest.len() != 64
        || !is_lower_hex(report_digest)
        || challenge.len() != 48
        || !is_lower_hex(challenge)
    {
        return Err(rejected("report-bound attestation nonce is malformed"));
    }
    Ok(format!("{report_digest}:{challenge}"))
}

fn read_bounded_response<R: Read>(reader: R) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    reader
        .take(MAX_ATTESTATION_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)?;
    if response.len() as u64 > MAX_ATTESTATION_RESPONSE_BYTES {
        return Err(rejected("attestation response exceeds the size limit"));
    }
    Ok(response)
}

fn request_attestation_at(socket_path: &Path, audience: &str, nonce: &str) -> Result<String> {
    let body = serde_json::to_vec(&TokenRequest {
        audience,
        token_type: "OIDC",
        nonces: [nonce],
    })?;
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    let response = read_bounded_response(stream)?;
    parse_attestation_response(&response)
}

fn parse_attestation_response(response: &[u8]) -> Result<String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| rejected("attestation response has no HTTP header boundary"))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| rejected("attestation response headers are not UTF-8"))?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| rejected("attestation response status is missing"))?;
    let mut status_parts = status.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let code = status_parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || code != "200" {
        return Err(rejected(format!("attestation request failed: {status}")));
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| rejected("attestation response header is malformed"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value
                .chars()
                .any(|character| character.is_control() && character != '\t')
        {
            return Err(rejected("attestation response header is malformed"));
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(rejected("attestation response repeats Content-Length"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| rejected("attestation Content-Length is malformed"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && transfer_encoding.replace(value.to_owned()).is_some()
        {
            return Err(rejected("attestation response repeats Transfer-Encoding"));
        }
    }

    let body = &response[header_end + 4..];
    let body = if let Some(encoding) = transfer_encoding {
        if content_length.is_some() || !encoding.eq_ignore_ascii_case("chunked") {
            return Err(rejected("attestation response framing is unsupported"));
        }
        decode_chunked_body(body)?
    } else if let Some(expected_length) = content_length {
        if body.len() != expected_length {
            return Err(rejected(
                "attestation response body does not match Content-Length",
            ));
        }
        body.to_vec()
    } else {
        // A response without explicit framing is delimited by the closed local
        // socket. The caller reads to EOF and imposes a total response bound.
        body.to_vec()
    };
    let body_text = std::str::from_utf8(&body)
        .map_err(|_| rejected("attestation response body is not UTF-8"))?
        .trim();
    if body_text.is_empty() {
        return Err(rejected("attestation response body is empty"));
    }
    let token = match serde_json::from_str::<Value>(body_text) {
        Ok(Value::String(token)) => token,
        Ok(Value::Object(value)) => value
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| rejected("attestation JSON response has no string token"))?
            .to_owned(),
        Ok(_) => return Err(rejected("attestation JSON response has no token")),
        Err(_) if body_text.starts_with('{') || body_text.starts_with('[') => {
            return Err(rejected("attestation JSON response is malformed"));
        }
        Err(_) => body_text.to_owned(),
    };
    if token.trim().is_empty() {
        return Err(rejected("attestation response token is empty"));
    }
    Ok(token)
}

fn build_envelope(
    report_bytes: &[u8],
    audience: String,
    nonce: String,
    token: String,
) -> Result<WorkloadEnvelope> {
    if audience.trim().is_empty() || nonce.trim().is_empty() || token.trim().is_empty() {
        return Err(rejected("attestation envelope identity is incomplete"));
    }
    let report: HostReport = serde_json::from_slice(report_bytes)?;
    if canonical_bytes(&report)? != report_bytes {
        return Err(rejected("maintenance report bytes are not canonical"));
    }
    report.validate()?;
    let report_digest = digest_bytes(report_bytes);
    let (_, challenge) = nonce
        .split_once(':')
        .ok_or_else(|| rejected("attestation nonce does not bind the report"))?;
    if report_bound_nonce(&report_digest, challenge)? != nonce {
        return Err(rejected("attestation nonce does not bind the report"));
    }
    Ok(WorkloadEnvelope {
        state_slice: STATE_SLICE,
        status: "machine_attested_report",
        claim_ceiling: "MachineAttestedReproduction; not IndependentReplication",
        attestation_issuer: "https://confidentialcomputing.googleapis.com",
        attestation_audience: audience,
        attestation_nonce: nonce,
        attestation_token: token,
        report_digest,
        report,
    })
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

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_checkout(path: &Path) -> Result<()> {
    create_private_dir(path)?;
    write_private(
        &path.join("README.md"),
        b"# Replication  \nDocumentation.   \n",
    )?;
    write_private(&path.join("neighbor.txt"), b"untouched\n")?;
    Ok(())
}

pub(crate) fn run_workload(
    root: &Path,
    runner: &Path,
    broker: &Path,
    evaluator: &Path,
    attestation_socket: &Path,
    implementation_revision: &str,
    audience: &str,
) -> Result<Vec<u8>> {
    let checkout = root.join("checkout");
    let keys = root.join("keys");
    let artifacts = root.join("artifacts");
    create_private_dir(root)?;
    create_private_dir(&keys)?;
    create_private_dir(&artifacts)?;
    create_checkout(&checkout)?;

    let bundle = root.join("frozen-bundle.json");
    let spec = root.join("runner-spec.json");
    let checkout_text = checkout
        .to_str()
        .ok_or_else(|| rejected("checkout path is invalid"))?;
    let bundle_text = bundle
        .to_str()
        .ok_or_else(|| rejected("bundle path is invalid"))?;
    let keys_text = keys
        .to_str()
        .ok_or_else(|| rejected("keys path is invalid"))?;
    let artifacts_text = artifacts
        .to_str()
        .ok_or_else(|| rejected("artifacts path is invalid"))?;
    let spec_text = spec
        .to_str()
        .ok_or_else(|| rejected("spec path is invalid"))?;
    let broker_text = broker
        .to_str()
        .ok_or_else(|| rejected("broker path is invalid"))?;
    let evaluator_text = evaluator
        .to_str()
        .ok_or_else(|| rejected("evaluator path is invalid"))?;
    let evaluator_seed = keys.join("evaluator.seed");
    let evaluator_seed_text = evaluator_seed
        .to_str()
        .ok_or_else(|| rejected("evaluator seed path is invalid"))?;
    let host_seed = keys.join("host.seed");
    let host_seed_text = host_seed
        .to_str()
        .ok_or_else(|| rejected("host seed path is invalid"))?;
    let operator_seed = keys.join("operator.seed");
    let operator_seed_text = operator_seed
        .to_str()
        .ok_or_else(|| rejected("operator seed path is invalid"))?;

    run(runner, &["keygen", keys_text])?;
    run(
        runner,
        &[
            "freeze",
            checkout_text,
            bundle_text,
            "maintenance-replication-v1",
            "4102444800",
            "1",
        ],
    )?;
    run(
        runner,
        &[
            "init",
            checkout_text,
            artifacts_text,
            broker_text,
            evaluator_text,
            evaluator_seed_text,
            "gcp-confidential-space",
            "machine-attested-runner",
            host_seed_text,
            operator_seed_text,
            implementation_revision,
            "4102444800",
            "1",
            "winner",
            spec_text,
        ],
    )?;
    run(runner, &["report", spec_text])?;

    let report_bytes = fs::read(artifacts.join("report.json"))?;
    let report_digest = digest_bytes(&report_bytes);
    let nonce = report_bound_nonce(&report_digest, &random_nonce()?)?;
    let token = request_attestation_at(attestation_socket, audience, &nonce)?;
    let envelope = build_envelope(&report_bytes, audience.to_owned(), nonce, token)?;
    canonical_bytes(&envelope)
}

fn main() {
    let result: Result<Vec<u8>> = (|| {
        let implementation_revision = std::env::var("IMPLEMENTATION_REVISION")
            .map_err(|_| rejected("IMPLEMENTATION_REVISION is required"))?;
        let audience =
            std::env::var("ATTESTATION_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_owned());
        run_workload(
            Path::new(ROOT),
            Path::new("/opt/maintenance/bin/maintenance_replication_runner"),
            Path::new("/opt/maintenance/bin/maintenance_broker"),
            Path::new("/opt/maintenance/bin/maintenance_evaluator"),
            Path::new(ATTESTATION_SOCKET),
            &implementation_revision,
            &audience,
        )
    })();
    match result {
        Ok(output) => match String::from_utf8(output) {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("machine-attested maintenance runner error: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("machine-attested maintenance runner error: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_envelope, decode_chunked_body, parse_attestation_response, read_bounded_response,
        report_bound_nonce, request_attestation_at, MAX_ATTESTATION_RESPONSE_BYTES,
    };
    use security_alignment_os::{canonical_bytes, digest_bytes};
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn decodes_attestation_chunked_body_and_trailers() {
        assert_eq!(
            decode_chunked_body(
                b"4;ext=value\r\natte\r\n5\r\nstate\r\n0\r\nX-Request: local\r\n\r\n"
            )
            .unwrap(),
            b"attestate"
        );
    }

    #[test]
    fn rejects_incomplete_or_trailing_chunked_bodies() {
        for body in [
            b"4\r\nabc".as_slice(),
            b"1\r\na\r\n0\r\n".as_slice(),
            b"0\r\n".as_slice(),
            b"0\r\n\r\ntrailing".as_slice(),
            b"z\r\n".as_slice(),
        ] {
            assert!(decode_chunked_body(body).is_err(), "accepted {body:?}");
        }
    }

    #[test]
    fn parses_only_successful_http_token_responses() {
        let body = b"{\"token\":\"synthetic-token\"}";
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let mut response = response.into_bytes();
        response.extend_from_slice(body);
        assert_eq!(
            parse_attestation_response(&response).unwrap(),
            "synthetic-token"
        );
        assert!(parse_attestation_response(b"HTTP/1.1 403 Forbidden\r\n\r\n{}").is_err());
        assert!(parse_attestation_response(b"not-http").is_err());
        assert!(parse_attestation_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n{\"token\":\"synthetic-token\"}"
        )
        .is_err());
        assert!(parse_attestation_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"
        )
        .is_err());
        assert!(parse_attestation_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n0\r\n\r\n"
        )
        .is_err());
        assert!(parse_attestation_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n{\"other\":true}"
        )
        .is_err());
        assert!(parse_attestation_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n{\"token\":true}"
        )
        .is_err());
    }

    #[test]
    fn bounds_attestation_response_reads() {
        let oversized = vec![b'x'; MAX_ATTESTATION_RESPONSE_BYTES as usize + 1];
        assert!(read_bounded_response(std::io::Cursor::new(oversized)).is_err());
        assert_eq!(
            read_bounded_response(std::io::Cursor::new(b"small".to_vec())).unwrap(),
            b"small"
        );
    }

    #[test]
    fn mocked_local_attestation_socket_round_trips_nonce_and_audience() {
        let directory = tempdir().expect("temporary directory");
        let socket_path = directory.path().join("teeserver.sock");
        let report_bytes = canonical_bytes(&serde_json::json!({"status": "fixture"}))
            .expect("canonical fixture report");
        let nonce = report_bound_nonce(&digest_bytes(&report_bytes), &"f".repeat(48))
            .expect("report-bound nonce");
        let expected_nonce = nonce.clone();
        let listener = UnixListener::bind(&socket_path).expect("bind local mock socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let request = read_request(&mut stream);
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("request header boundary");
            let request_body: Value =
                serde_json::from_slice(&request[header_end + 4..]).expect("request JSON");
            assert_eq!(
                request_body["audience"],
                "https://example.invalid/local-test"
            );
            assert_eq!(request_body["token_type"], "OIDC");
            assert_eq!(request_body["nonces"][0], expected_nonce);

            let body = b"{\"token\":\"synthetic-only-token\"}";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                body.len()
            )
            .expect("write mock response headers");
            stream.write_all(body).expect("write mock response body");
            stream
                .write_all(b"\r\n0\r\n\r\n")
                .expect("finish mock response");
        });

        let token =
            request_attestation_at(&socket_path, "https://example.invalid/local-test", &nonce)
                .expect("mocked local attestation request");
        assert_eq!(token, "synthetic-only-token");
        server.join().expect("mock server");
    }

    fn read_request(stream: &mut UnixStream) -> Vec<u8> {
        let mut request = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read client request");
            assert_ne!(read, 0, "client closed before request completed");
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = std::str::from_utf8(&request[..header_end]).expect("request headers");
            assert!(headers.starts_with("POST /v1/token HTTP/1.1"));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
                .expect("content length header");
            if request.len() >= header_end + 4 + content_length {
                request.truncate(header_end + 4 + content_length);
                return request;
            }
        }
    }

    #[test]
    fn envelope_rejects_noncanonical_and_invalid_host_reports() {
        assert!(build_envelope(
            b"{ \"status\":\"local-fixture\"}",
            "audience".into(),
            "nonce".into(),
            "synthetic-token".into(),
        )
        .is_err());
        let report = canonical_bytes(&serde_json::json!({"status": "local-fixture"})).unwrap();
        assert!(build_envelope(
            &report,
            "audience".into(),
            "nonce".into(),
            "synthetic-token".into(),
        )
        .is_err());
        assert!(build_envelope(&report, String::new(), String::new(), String::new()).is_err());
    }
}
