//! End-to-end producer for the fixed maintenance replication packet.
//!
//! State slice: security-alignment-os-foundation-v1.
//!
//! Usage:
//!   maintenance_replication_runner keygen KEY_DIR
//!   maintenance_replication_runner keygen-evaluator KEY_DIR
//!   maintenance_replication_runner keygen-host KEY_DIR
//!   maintenance_replication_runner freeze CHECKOUT OUTPUT REQUEST_ID LEASE_EXPIRES_AT NONCE
//!   maintenance_replication_runner init CHECKOUT ARTIFACT_DIR BROKER EVALUATOR EVALUATOR_SEED HOST_ID OPERATOR_ID HOST_SEED OPERATOR_SEED IMPLEMENTATION_REVISION LEASE_EXPIRES_AT NONCE CONTENTION_ROLE SPEC_OUTPUT
//!   maintenance_replication_runner report SPEC
//!   maintenance_replication_runner packet FROZEN_BUNDLE REPORT_A REPORT_B OUTPUT

use security_alignment_os::maintenance_replication_runner::{
    assemble_packet, freeze_checkout, generate_seed_file, load_frozen_bundle, load_host_report,
    load_runner_spec, FrozenBundle, RunnerSpec, RUNNER_VERSION,
};
use security_alignment_os::{canonical_bytes, Error, Result, STATE_SLICE};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

fn usage() -> ! {
    eprintln!(
        "usage:
  maintenance_replication_runner keygen KEY_DIR
  maintenance_replication_runner keygen-evaluator KEY_DIR
  maintenance_replication_runner keygen-host KEY_DIR
  maintenance_replication_runner freeze CHECKOUT OUTPUT REQUEST_ID LEASE_EXPIRES_AT NONCE
  maintenance_replication_runner init CHECKOUT ARTIFACT_DIR BROKER EVALUATOR EVALUATOR_SEED HOST_ID OPERATOR_ID HOST_SEED OPERATOR_SEED IMPLEMENTATION_REVISION LEASE_EXPIRES_AT NONCE CONTENTION_ROLE SPEC_OUTPUT
  maintenance_replication_runner report SPEC
  maintenance_replication_runner packet FROZEN_BUNDLE REPORT_A REPORT_B OUTPUT"
    );
    std::process::exit(2)
}

fn next(args: &mut impl Iterator<Item = std::ffi::OsString>, name: &str) -> Result<String> {
    args.next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| Error::Rejected(format!("missing {name}")))
}

fn path(value: String, name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Error::Rejected(format!("{name} must be absolute")));
    }
    Ok(path)
}

fn number<T: std::str::FromStr>(value: String, name: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| Error::Rejected(format!("{name} is invalid")))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Rejected("output has no parent".into()))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Serialize)]
struct Output<'a> {
    status: &'a str,
    verdict: Option<&'a str>,
    path: Option<String>,
    id: Option<&'a str>,
}

fn emit(output: Output<'_>) {
    println!(
        "{}",
        serde_json::to_string(&output).expect("runner output serialization")
    );
}

fn prepare_key_directory(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_keygen_output(directory: PathBuf, seeds: &[(&str, u8)]) -> Result<()> {
    prepare_key_directory(&directory)?;
    for (name, marker) in seeds {
        generate_seed_file(&directory.join(name), *marker)?;
    }
    Ok(())
}

fn parse_role(
    value: String,
) -> Result<security_alignment_os::maintenance_replication::ScenarioRole> {
    match value.as_str() {
        "winner" => Ok(security_alignment_os::maintenance_replication::ScenarioRole::Winner),
        "contender" => Ok(security_alignment_os::maintenance_replication::ScenarioRole::Contender),
        _ => Err(Error::Rejected(
            "contention role must be winner or contender".into(),
        )),
    }
}

fn main() {
    let result: Result<()> = (|| {
        let mut args = std::env::args_os();
        let _program = args.next();
        let command = args.next().and_then(|value| value.into_string().ok());
        let result = match command.as_deref() {
            Some("keygen") => {
                let directory = path(next(&mut args, "key directory")?, "key directory")?;
                if args.next().is_some() {
                    usage();
                }
                create_keygen_output(
                    directory.clone(),
                    &[
                        ("evaluator.seed", 1),
                        ("host.seed", 2),
                        ("operator.seed", 3),
                    ],
                )?;
                emit(Output {
                    status: "keys_created",
                    verdict: None,
                    path: Some(directory.display().to_string()),
                    id: None,
                });
                Ok(())
            }
            Some("keygen-evaluator") => {
                let directory = path(
                    next(&mut args, "evaluator key directory")?,
                    "evaluator key directory",
                )?;
                if args.next().is_some() {
                    usage();
                }
                create_keygen_output(directory.clone(), &[("evaluator.seed", 1)])?;
                emit(Output {
                    status: "evaluator_key_created",
                    verdict: None,
                    path: Some(directory.display().to_string()),
                    id: None,
                });
                Ok(())
            }
            Some("keygen-host") => {
                let directory = path(next(&mut args, "host key directory")?, "host key directory")?;
                if args.next().is_some() {
                    usage();
                }
                create_keygen_output(directory.clone(), &[("host.seed", 2), ("operator.seed", 3)])?;
                emit(Output {
                    status: "host_operator_keys_created",
                    verdict: None,
                    path: Some(directory.display().to_string()),
                    id: None,
                });
                Ok(())
            }
            Some("freeze") => {
                let checkout = path(next(&mut args, "checkout")?, "checkout")?;
                let output = path(next(&mut args, "output")?, "output")?;
                let request_id = next(&mut args, "request id")?;
                let lease = number(next(&mut args, "lease")?, "lease")?;
                let nonce = number(next(&mut args, "nonce")?, "nonce")?;
                if args.next().is_some() {
                    usage();
                }
                let bundle = freeze_checkout(&checkout, &request_id, lease, nonce)?;
                write_private(&output, &canonical_bytes(&bundle)?)?;
                emit(Output {
                    status: "frozen_bundle_created",
                    verdict: None,
                    path: Some(output.display().to_string()),
                    id: None,
                });
                Ok(())
            }
            Some("init") => {
                let checkout = path(next(&mut args, "checkout")?, "checkout")?;
                let artifact_dir =
                    path(next(&mut args, "artifact directory")?, "artifact directory")?;
                let broker = path(next(&mut args, "broker")?, "broker")?;
                let evaluator = path(next(&mut args, "evaluator")?, "evaluator")?;
                let evaluator_seed = path(next(&mut args, "evaluator seed")?, "evaluator seed")?;
                let host_id = next(&mut args, "host id")?;
                let operator_id = next(&mut args, "operator id")?;
                let host_seed = path(next(&mut args, "host seed")?, "host seed")?;
                let operator_seed = path(next(&mut args, "operator seed")?, "operator seed")?;
                let revision = next(&mut args, "implementation revision")?;
                let lease = number(next(&mut args, "lease")?, "lease")?;
                let nonce = number(next(&mut args, "nonce")?, "nonce")?;
                let contention_role = parse_role(next(&mut args, "contention role")?)?;
                let spec_output = path(next(&mut args, "spec output")?, "spec output")?;
                if args.next().is_some() {
                    usage();
                }
                let frozen =
                    freeze_checkout(&checkout, "maintenance-replication-v1", lease, nonce)?;
                let spec = RunnerSpec {
                    version: RUNNER_VERSION,
                    state_slice: STATE_SLICE.into(),
                    operation:
                        security_alignment_os::maintenance_replication::FIXED_OPERATION_IDENTITY
                            .into(),
                    process_version: security_alignment_os::maintenance_process::PROCESS_VERSION,
                    checkout_source: fs::canonicalize(checkout)?,
                    artifact_dir,
                    maintenance_broker_path: broker,
                    evaluator_path: evaluator,
                    evaluator_seed_path: evaluator_seed,
                    host_id,
                    operator_id,
                    host_seed_path: host_seed,
                    operator_seed_path: operator_seed,
                    implementation_revision: revision,
                    evaluator_timeout_ms: 10_000,
                    contention_role,
                    frozen,
                };
                write_private(&spec_output, &canonical_bytes(&spec)?)?;
                emit(Output {
                    status: "runner_spec_created",
                    verdict: None,
                    path: Some(spec_output.display().to_string()),
                    id: None,
                });
                Ok(())
            }
            Some("report") => {
                let spec_path = path(next(&mut args, "spec")?, "spec")?;
                if args.next().is_some() {
                    usage();
                }
                let spec = load_runner_spec(&spec_path)?;
                let report =
                    security_alignment_os::maintenance_replication_runner::run_host(&spec)?;
                emit(Output {
                    status: "host_report_created",
                    verdict: Some("LocalOnly"),
                    path: Some(spec.artifact_dir.join("report.json").display().to_string()),
                    id: Some(&report.report_id),
                });
                Ok(())
            }
            Some("packet") => {
                let bundle_path = path(next(&mut args, "frozen bundle")?, "frozen bundle")?;
                let first_path = path(next(&mut args, "first report")?, "first report")?;
                let second_path = path(next(&mut args, "second report")?, "second report")?;
                let output = path(next(&mut args, "packet output")?, "packet output")?;
                if args.next().is_some() {
                    usage();
                }
                let bundle: FrozenBundle = load_frozen_bundle(&bundle_path)?;
                let first = load_host_report(&first_path)?;
                let second = load_host_report(&second_path)?;
                let packet = assemble_packet(&bundle, first, second)?;
                write_private(&output, &packet.canonical_bytes()?)?;
                emit(Output {
                    status: "valid_local_packet",
                    verdict: Some("Inconclusive"),
                    path: Some(output.display().to_string()),
                    id: Some(&packet.packet_id),
                });
                Ok(())
            }
            Some(_) | None => usage(),
        };
        result
    })();
    if let Err(error) = result {
        eprintln!("maintenance replication runner error: {error}");
        std::process::exit(1);
    }
}
