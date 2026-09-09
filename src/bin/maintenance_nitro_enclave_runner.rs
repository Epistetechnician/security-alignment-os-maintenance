//! Machine-attested fixed-operation runner for AWS Nitro Enclaves.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The enclave runs the existing fixed-operation replication runner, binds the
//! resulting report digest into an AWS Nitro attestation document, and sends a
//! canonical envelope to the parent over vsock. No network, credentials, or
//! provider calls are available inside the enclave.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use security_alignment_os::{canonical_bytes, digest_bytes, Error, Result, STATE_SLICE};
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const ROOT: &str = "/tmp/maintenance";
const CHECKOUT: &str = "/tmp/maintenance/checkout";
const KEYS: &str = "/tmp/maintenance/keys";
const ARTIFACTS: &str = "/tmp/maintenance/artifacts";
#[cfg(target_os = "linux")]
const PARENT_CID: u32 = 3;
#[cfg(target_os = "linux")]
const PARENT_PORT: u32 = 5000;
const DEFAULT_AUDIENCE: &str = "aws-nitro-enclaves://maintenance-replication-v1";

#[derive(Serialize)]
struct WorkloadEnvelope {
    state_slice: &'static str,
    status: &'static str,
    claim_ceiling: &'static str,
    attestation_issuer: &'static str,
    attestation_audience: String,
    attestation_nonce: String,
    attestation_user_data: String,
    attestation_document_hex: String,
    attestation_document_digest: String,
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
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

fn request_attestation(user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let fd = nsm_init();
    if fd < 0 {
        return Err(rejected("Nitro Secure Module initialization failed"));
    }
    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data: Some(ByteBuf::from(user_data.to_vec())),
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            public_key: None,
        },
    );
    nsm_exit(fd);
    match response {
        Response::Attestation { document } if !document.is_empty() => Ok(document),
        Response::Attestation { .. } => Err(rejected("Nitro attestation document is empty")),
        Response::Error(error) => Err(rejected(format!("Nitro attestation failed: {error:?}"))),
        other => Err(rejected(format!("unexpected Nitro response: {other:?}"))),
    }
}

fn run(binary: &Path, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(binary).args(args).output()?;
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

fn create_checkout() -> Result<()> {
    create_private_dir(Path::new(CHECKOUT))?;
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

#[cfg(target_os = "linux")]
fn send_to_parent(bytes: &[u8]) -> Result<()> {
    use std::mem::size_of;
    use std::os::fd::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(rejected("could not open the vsock socket"));
    }
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_port = PARENT_PORT;
    address.svm_cid = PARENT_CID;
    let connected = unsafe {
        libc::connect(
            fd,
            &address as *const libc::sockaddr_vm as *const libc::sockaddr,
            size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if connected != 0 {
        unsafe { libc::close(fd) };
        return Err(rejected("could not connect to the parent over vsock"));
    }
    let mut stream = unsafe { fs::File::from_raw_fd(fd) };
    stream.write_all(bytes)?;
    stream.sync_all().ok();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn send_to_parent(bytes: &[u8]) -> Result<()> {
    let output =
        String::from_utf8(bytes.to_vec()).map_err(|_| rejected("envelope is not UTF-8"))?;
    println!("{output}");
    Ok(())
}

fn main() {
    let result: Result<()> = (|| {
        let implementation_revision = std::env::var("IMPLEMENTATION_REVISION")
            .map_err(|_| rejected("IMPLEMENTATION_REVISION is required"))?;
        let audience =
            std::env::var("ATTESTATION_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_owned());
        let nonce = random_nonce()?;

        create_private_dir(Path::new(ROOT))?;
        create_private_dir(Path::new(KEYS))?;
        create_private_dir(Path::new(ARTIFACTS))?;
        create_checkout()?;

        let runner = Path::new("/opt/maintenance/bin/maintenance_replication_runner");
        let broker = Path::new("/opt/maintenance/bin/maintenance_broker");
        let evaluator = Path::new("/opt/maintenance/bin/maintenance_evaluator");
        let spec = Path::new(ROOT).join("runner-spec.json");
        run(runner, &["keygen", KEYS])?;
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
                "aws-nitro-enclave",
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
        let report_digest = digest_bytes(&report_bytes);
        let attestation_document = request_attestation(report_digest.as_bytes(), nonce.as_bytes())?;
        let envelope = WorkloadEnvelope {
            state_slice: STATE_SLICE,
            status: "machine_attested_report",
            claim_ceiling: "MachineAttestedReproduction; not IndependentReplication",
            attestation_issuer: "aws-nitro-secure-module",
            attestation_audience: audience,
            attestation_nonce: nonce,
            attestation_user_data: report_digest.clone(),
            attestation_document_digest: digest_bytes(&attestation_document),
            attestation_document_hex: hex(&attestation_document),
            report_digest,
            report,
        };
        send_to_parent(&canonical_bytes(&envelope)?)
    })();
    if let Err(error) = result {
        eprintln!("machine-attested Nitro runner error: {error}");
        std::process::exit(1);
    }
}
