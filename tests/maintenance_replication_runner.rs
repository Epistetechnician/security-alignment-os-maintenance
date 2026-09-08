//! Real-process replication runner checks.
//!
//! State slice: security-alignment-os-foundation-v1.

use security_alignment_os::maintenance_replication::{ScenarioRole, REQUIRED_SCENARIOS};
use security_alignment_os::maintenance_replication_runner::{
    assemble_packet, baseline_manifest, freeze_checkout, generate_seed_file, run_host,
    FrozenBundle, RunnerSpec,
};
use security_alignment_os::STATE_SLICE;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::{tempdir, TempDir};

fn mode(path: &PathBuf, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Fixture {
    root: TempDir,
    source: PathBuf,
    evaluator: PathBuf,
    evaluator_seed: PathBuf,
    bundle: FrozenBundle,
}

impl Fixture {
    fn new() -> Self {
        let root = tempdir().unwrap();
        mode(&root.path().to_path_buf(), 0o700);
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        mode(&source, 0o700);
        fs::write(
            source.join("README.md"),
            b"# Replication  \nDocumentation.   \n",
        )
        .unwrap();
        fs::write(source.join("neighbor.txt"), b"untouched\n").unwrap();
        let evaluator = root.path().join("maintenance_evaluator");
        fs::copy(env!("CARGO_BIN_EXE_maintenance_evaluator"), &evaluator).unwrap();
        mode(&evaluator, 0o700);
        let evaluator_seed = root.path().join("evaluator.seed");
        generate_seed_file(&evaluator_seed, 1).unwrap();
        let bundle = freeze_checkout(
            &source,
            "maintenance-replication-v1",
            now().saturating_add(3_600),
            1,
        )
        .unwrap();
        Self {
            root,
            source,
            evaluator,
            evaluator_seed,
            bundle,
        }
    }

    fn spec(&self, name: &str, role: ScenarioRole) -> RunnerSpec {
        let artifact_dir = self.root.path().join(name);
        let key_dir = self.root.path().join(format!("{name}-keys"));
        fs::create_dir(&key_dir).unwrap();
        mode(&key_dir, 0o700);
        let host_seed = key_dir.join("host.seed");
        let operator_seed = key_dir.join("operator.seed");
        generate_seed_file(&host_seed, 2).unwrap();
        generate_seed_file(&operator_seed, 3).unwrap();
        RunnerSpec {
            version: 1,
            state_slice: STATE_SLICE.into(),
            operation: "normalize-trailing-ascii-spaces-v1".into(),
            process_version: 2,
            checkout_source: self.source.clone(),
            artifact_dir,
            maintenance_broker_path: PathBuf::from(env!("CARGO_BIN_EXE_maintenance_broker")),
            evaluator_path: self.evaluator.clone(),
            evaluator_seed_path: self.evaluator_seed.clone(),
            host_id: name.into(),
            operator_id: format!("{name}-operator"),
            host_seed_path: host_seed,
            operator_seed_path: operator_seed,
            implementation_revision: "a".repeat(40),
            evaluator_timeout_ms: 10_000,
            contention_role: role,
            frozen: self.bundle.clone(),
        }
    }
}

#[test]
fn host_runner_executes_and_records_all_real_scenarios() {
    let fixture = Fixture::new();
    let spec = fixture.spec("host-a", ScenarioRole::Winner);
    let report = run_host(&spec).expect("real host report");
    report.validate().expect("signed report");
    assert_eq!(report.scenarios.len(), REQUIRED_SCENARIOS.len());
    assert_eq!(
        fs::read_dir(spec.artifact_dir.join("evidence"))
            .unwrap()
            .count(),
        REQUIRED_SCENARIOS.len()
    );
    assert_eq!(
        fs::read(fixture.source.join("README.md")).unwrap(),
        b"# Replication  \nDocumentation.   \n"
    );
    assert!(spec.artifact_dir.join("report.json").is_file());
    assert_eq!(
        baseline_manifest(&fixture.source).unwrap(),
        fixture.bundle.baseline_manifest
    );
}

#[test]
fn same_host_packet_rehearsal_remains_inconclusive() {
    let fixture = Fixture::new();
    let first = run_host(&fixture.spec("host-a", ScenarioRole::Winner)).expect("host A report");
    let second = run_host(&fixture.spec("host-b", ScenarioRole::Contender))
        .expect("host B rehearsal report");
    let packet = assemble_packet(&fixture.bundle, first, second).expect("packet");
    let bytes = packet.canonical_bytes().expect("canonical packet");
    assert_eq!(
        security_alignment_os::maintenance_replication::ReplicationPacket::from_canonical_bytes(
            &bytes
        )
        .unwrap(),
        packet
    );
    assert_eq!(packet.reports.len(), 2);
}

#[test]
fn seed_generation_never_overwrites_existing_key_material() {
    let directory = tempdir().unwrap();
    mode(&directory.path().to_path_buf(), 0o700);
    let seed = directory.path().join("host.seed");
    fs::write(&seed, [7_u8; 32]).unwrap();
    mode(&seed, 0o600);
    assert!(generate_seed_file(&seed, 9).is_err());
    assert_eq!(fs::read(seed).unwrap(), [7_u8; 32]);
}
