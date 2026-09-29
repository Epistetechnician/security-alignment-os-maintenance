//! Machine-attested fixed-operation runner for AWS Nitro Enclaves.
//!
//! State slices: `security-alignment-os-foundation-v1` and
//! `maintenance-platform-runner-hermetic-e2e-v1`.
//!
//! The enclave runs the existing fixed-operation replication runner, binds the
//! resulting report digest into an AWS Nitro attestation document, and sends a
//! canonical envelope to the parent over vsock. No network, credentials, or
//! provider calls are available inside the enclave.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use security_alignment_os::maintenance_replication::HostReport;
use security_alignment_os::{canonical_bytes, digest_bytes, Error, Result, STATE_SLICE};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const ROOT: &str = "/tmp/maintenance";
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
    implementation_revision: String,
    source_tree_sha256: String,
    report: HostReport,
}

#[derive(Serialize)]
struct AttestationBinding<'a> {
    implementation_revision: &'a str,
    report_digest: &'a str,
    source_tree_sha256: &'a str,
}

pub(crate) struct WorkloadConfig<'a> {
    pub(crate) root: &'a Path,
    pub(crate) runner: &'a Path,
    pub(crate) broker: &'a Path,
    pub(crate) evaluator: &'a Path,
    pub(crate) implementation_revision: &'a str,
    pub(crate) source_tree_sha256: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) audience: &'a str,
}

fn rejected(message: impl Into<String>) -> Error {
    Error::Rejected(message.into())
}

fn build_envelope(
    report_bytes: &[u8],
    attestation_document: &[u8],
    attested_user_data: &str,
    implementation_revision: &str,
    source_tree_sha256: &str,
    nonce: String,
    audience: String,
) -> Result<WorkloadEnvelope> {
    if attestation_document.is_empty() || nonce.trim().is_empty() || audience.trim().is_empty() {
        return Err(rejected(
            "Nitro attestation envelope identity is incomplete",
        ));
    }
    let report: HostReport = serde_json::from_slice(report_bytes)?;
    if canonical_bytes(&report)? != report_bytes {
        return Err(rejected("maintenance report bytes are not canonical"));
    }
    report.validate()?;
    validate_report_revision(&report.implementation_revision, implementation_revision)?;
    validate_source_digest(source_tree_sha256)?;
    let report_digest = digest_bytes(report_bytes);
    let expected_user_data =
        attestation_binding_digest(implementation_revision, &report_digest, source_tree_sha256)?;
    if attested_user_data != expected_user_data {
        return Err(rejected(
            "Nitro user data does not bind the report and image source identity",
        ));
    }
    Ok(WorkloadEnvelope {
        state_slice: STATE_SLICE,
        status: "machine_attested_report",
        claim_ceiling: "MachineAttestedReproduction; not IndependentReplication",
        attestation_issuer: "aws-nitro-secure-module",
        attestation_audience: audience,
        attestation_nonce: nonce,
        attestation_user_data: expected_user_data,
        attestation_document_digest: digest_bytes(attestation_document),
        attestation_document_hex: hex(attestation_document),
        report_digest,
        implementation_revision: implementation_revision.to_owned(),
        source_tree_sha256: source_tree_sha256.to_owned(),
        report,
    })
}

fn validate_implementation_revision(revision: &str) -> Result<()> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected(
            "Nitro image revision must be a 40-character lowercase Git ID",
        ));
    }
    Ok(())
}

fn validate_report_revision(report_revision: &str, image_revision: &str) -> Result<()> {
    validate_implementation_revision(image_revision)?;
    if report_revision != image_revision {
        return Err(rejected(
            "Nitro report revision does not match the embedded image revision",
        ));
    }
    Ok(())
}

fn validate_source_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected(
            "Nitro image source identity must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn attestation_binding_digest(
    implementation_revision: &str,
    report_digest: &str,
    source_tree_sha256: &str,
) -> Result<String> {
    let binding = AttestationBinding {
        implementation_revision,
        report_digest,
        source_tree_sha256,
    };
    Ok(digest_bytes(&canonical_bytes(&binding)?))
}

fn reject_runtime_identity_overrides(
    implementation_revision_present: bool,
    source_tree_sha256_present: bool,
) -> Result<()> {
    if implementation_revision_present || source_tree_sha256_present {
        return Err(rejected(
            "Nitro image identity is embedded at build time; runtime overrides are forbidden",
        ));
    }
    Ok(())
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

fn create_checkout(path: &Path) -> Result<()> {
    create_private_dir(path)?;
    write_private(
        &path.join("README.md"),
        b"# Replication  \nDocumentation.   \n",
    )?;
    write_private(&path.join("neighbor.txt"), b"untouched\n")?;
    Ok(())
}

pub(crate) fn run_workload<F>(config: WorkloadConfig<'_>, attest: F) -> Result<Vec<u8>>
where
    F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>>,
{
    let WorkloadConfig {
        root,
        runner,
        broker,
        evaluator,
        implementation_revision,
        source_tree_sha256,
        nonce,
        audience,
    } = config;
    let checkout = root.join("checkout");
    let keys = root.join("keys");
    let artifacts = root.join("artifacts");
    let spec = root.join("runner-spec.json");
    create_private_dir(root)?;
    create_private_dir(&keys)?;
    create_private_dir(&artifacts)?;
    create_checkout(&checkout)?;

    let keys_text = keys
        .to_str()
        .ok_or_else(|| rejected("keys path is invalid"))?;
    let checkout_text = checkout
        .to_str()
        .ok_or_else(|| rejected("checkout path is invalid"))?;
    let artifacts_text = artifacts
        .to_str()
        .ok_or_else(|| rejected("artifacts path is invalid"))?;
    let evaluator_seed = keys.join("evaluator.seed");
    let host_seed = keys.join("host.seed");
    let operator_seed = keys.join("operator.seed");
    let evaluator_seed_text = evaluator_seed
        .to_str()
        .ok_or_else(|| rejected("evaluator seed path is invalid"))?;
    let host_seed_text = host_seed
        .to_str()
        .ok_or_else(|| rejected("host seed path is invalid"))?;
    let operator_seed_text = operator_seed
        .to_str()
        .ok_or_else(|| rejected("operator seed path is invalid"))?;
    let spec_text = spec
        .to_str()
        .ok_or_else(|| rejected("spec path is invalid"))?;
    let broker_text = broker
        .to_str()
        .ok_or_else(|| rejected("broker path is invalid"))?;
    let evaluator_text = evaluator
        .to_str()
        .ok_or_else(|| rejected("evaluator path is invalid"))?;

    run(runner, &["keygen", keys_text])?;
    run(
        runner,
        &[
            "init",
            checkout_text,
            artifacts_text,
            broker_text,
            evaluator_text,
            evaluator_seed_text,
            "aws-nitro-enclave",
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
    let attestation_user_data =
        attestation_binding_digest(implementation_revision, &report_digest, source_tree_sha256)?;
    let attestation_document = attest(attestation_user_data.as_bytes(), nonce.as_bytes())?;
    let envelope = build_envelope(
        &report_bytes,
        &attestation_document,
        &attestation_user_data,
        implementation_revision,
        source_tree_sha256,
        nonce.to_owned(),
        audience.to_owned(),
    )?;
    canonical_bytes(&envelope)
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
        reject_runtime_identity_overrides(
            std::env::var_os("IMPLEMENTATION_REVISION").is_some(),
            std::env::var_os("SOURCE_TREE_SHA256").is_some(),
        )?;
        let implementation_revision = option_env!("NITRO_IMAGE_IMPLEMENTATION_REVISION")
            .ok_or_else(|| rejected("Nitro image revision was not embedded at build time"))?;
        let source_tree_sha256 = option_env!("NITRO_IMAGE_SOURCE_TREE_SHA256")
            .ok_or_else(|| rejected("Nitro image source digest was not embedded at build time"))?;
        let audience =
            std::env::var("ATTESTATION_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_owned());
        let nonce = random_nonce()?;
        let runner = Path::new("/opt/maintenance/bin/maintenance_replication_runner");
        let broker = Path::new("/opt/maintenance/bin/maintenance_broker");
        let evaluator = Path::new("/opt/maintenance/bin/maintenance_evaluator");
        let envelope = run_workload(
            WorkloadConfig {
                root: Path::new(ROOT),
                runner,
                broker,
                evaluator,
                implementation_revision,
                source_tree_sha256,
                nonce: &nonce,
                audience: &audience,
            },
            request_attestation,
        )?;
        send_to_parent(&envelope)
    })();
    if let Err(error) = result {
        eprintln!("machine-attested Nitro runner error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{build_envelope, reject_runtime_identity_overrides, validate_report_revision};
    use security_alignment_os::canonical_bytes;
    use serde_json::json;

    #[test]
    fn envelope_rejects_noncanonical_and_invalid_host_reports() {
        assert!(build_envelope(
            b"{ \"status\":\"local-fixture\"}",
            b"synthetic-nsm-document",
            &"0".repeat(64),
            &"a".repeat(40),
            &"a".repeat(64),
            "synthetic-nonce".into(),
            "audience".into(),
        )
        .is_err());

        let report = canonical_bytes(&json!({"status": "local-fixture"})).unwrap();
        assert!(build_envelope(
            &report,
            b"synthetic-nsm-document",
            &"0".repeat(64),
            &"a".repeat(40),
            &"a".repeat(64),
            "synthetic-nonce".into(),
            "audience".into(),
        )
        .is_err());
    }

    #[test]
    fn runtime_identity_overrides_are_rejected() {
        assert!(reject_runtime_identity_overrides(false, false).is_ok());
        assert!(reject_runtime_identity_overrides(true, false).is_err());
        assert!(reject_runtime_identity_overrides(false, true).is_err());
        assert!(reject_runtime_identity_overrides(true, true).is_err());
    }

    #[test]
    fn report_revision_must_match_the_embedded_image_revision() {
        let revision = "a".repeat(40);
        assert!(validate_report_revision(&revision, &revision).is_ok());
        assert!(validate_report_revision(&"b".repeat(40), &revision).is_err());
        assert!(validate_report_revision(&revision, "not-a-revision").is_err());
    }
}
