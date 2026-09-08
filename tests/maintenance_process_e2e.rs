//! Fixed maintenance process checks. State slice: security-alignment-os-foundation-v1.
#![cfg(unix)]

use ed25519_dalek::SigningKey;
use security_alignment_os::digest_bytes;
use security_alignment_os::maintenance_process::{
    checkout_baseline_digest, fixed_input_digest, fixed_policy_digest, fixed_tests_digest, Config,
    Request,
};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

const BEFORE: &[u8] = b"# Maintenance  \r\nUseful documentation.   \nlast line  ";
const AFTER: &[u8] = b"# Maintenance\r\nUseful documentation.\nlast line";

struct Fixture {
    _root: TempDir,
    config: Config,
    request: Request,
    config_path: PathBuf,
    request_path: PathBuf,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        mode(root.path(), 0o700);
        let root_path = fs::canonicalize(root.path()).unwrap();
        let checkout = root_path.join("checkout");
        let state = root_path.join("state");
        for path in [&checkout, &state] {
            fs::create_dir(path).unwrap();
            mode(path, 0o700);
        }
        fs::write(checkout.join("README.md"), BEFORE).unwrap();
        fs::write(checkout.join("neighbor.txt"), b"untouched\n").unwrap();
        let evaluator = root.path().join("evaluator");
        fs::copy(env!("CARGO_BIN_EXE_maintenance_evaluator"), &evaluator).unwrap();
        mode(&evaluator, 0o700);
        let seed_path = root.path().join("seed");
        // Synthetic test key, never used as independent operator evidence.
        let seed = [17u8; 32];
        fs::write(&seed_path, seed).unwrap();
        mode(&seed_path, 0o600);
        let public_key: String = SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let config = Config {
            evaluator_path: evaluator.clone(),
            evaluator_seed_path: seed_path,
            evaluator_executable_digest: digest_bytes(&fs::read(evaluator).unwrap()),
            evaluator_public_key: public_key,
            evaluator_input_digest: fixed_input_digest(),
            evaluator_tests_digest: fixed_tests_digest(),
            policy_digest: fixed_policy_digest(),
            checkout_root: checkout.clone(),
            state_dir: state,
            cancellation_file: root.path().join("cancel"),
            evaluator_timeout_ms: 2000,
        };
        let request = Request {
            request_id: "trim-doc-v1".into(),
            relative_path: "README.md".into(),
            before_bytes: BEFORE.to_vec(),
            before_digest: digest_bytes(BEFORE),
            after_bytes: AFTER.to_vec(),
            after_digest: digest_bytes(AFTER),
            checkout_baseline_digest: checkout_baseline_digest(&checkout).unwrap(),
            lease_expires_at: now() + 60,
            nonce: 1,
        };
        let config_path = root.path().join("config.json");
        let request_path = root.path().join("request.json");
        Self {
            _root: root,
            config,
            request,
            config_path,
            request_path,
        }
    }

    fn invoke(&self, failpoint: Option<&str>) -> Output {
        fs::write(&self.config_path, serde_json::to_vec(&self.config).unwrap()).unwrap();
        mode(&self.config_path, 0o600);
        fs::write(
            &self.request_path,
            serde_json::to_vec(&self.request).unwrap(),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_maintenance_broker"));
        command
            .arg(&self.config_path)
            .arg(&self.request_path)
            .env_clear();
        if let Some(value) = failpoint {
            command.env("MAINTENANCE_TEST_FAILPOINT", value);
        }
        command.output().unwrap()
    }

    fn run(&self) -> Value {
        let output = self.invoke(None);
        assert!(
            output.status.success(),
            "broker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn assert_baseline(&self) {
        assert_eq!(
            fs::read(self.config.checkout_root.join("README.md")).unwrap(),
            BEFORE
        );
        assert_eq!(
            fs::read(self.config.checkout_root.join("neighbor.txt")).unwrap(),
            b"untouched\n"
        );
    }
}

#[test]
fn useful_patch_and_replay_across_processes() {
    let fixture = Fixture::new();
    let result = fixture.run();
    assert_eq!(result["status"], "Applied", "{result}");
    assert_eq!(result["after_digest"], digest_bytes(AFTER));
    assert!(result["receipt_digest"].as_str().is_some());
    assert_eq!(
        fs::read(fixture.config.checkout_root.join("README.md")).unwrap(),
        AFTER
    );
    assert_eq!(
        fs::read(fixture.config.checkout_root.join("neighbor.txt")).unwrap(),
        b"untouched\n"
    );
    assert_eq!(fixture.run()["status"], "Quarantined");
}

#[test]
fn invalid_candidate_and_stale_baseline_never_mutate() {
    let mut fixture = Fixture::new();
    fixture.request.after_bytes = b"unauthorized content".to_vec();
    fixture.request.after_digest = digest_bytes(&fixture.request.after_bytes);
    assert_eq!(fixture.run()["status"], "Quarantined");
    fixture.assert_baseline();
    let mut fixture = Fixture::new();
    fixture.request.checkout_baseline_digest = "0".repeat(64);
    assert_eq!(fixture.run()["status"], "Quarantined");
    fixture.assert_baseline();
}

#[test]
fn expired_cancelled_or_changed_evaluator_requirements_never_mutate() {
    for case in 0..5 {
        let mut fixture = Fixture::new();
        match case {
            0 => fixture.request.lease_expires_at = now(),
            1 => fs::write(&fixture.config.cancellation_file, b"cancel").unwrap(),
            2 => fixture.config.evaluator_executable_digest = "0".repeat(64),
            3 => fixture.config.evaluator_public_key = "0".repeat(64),
            _ => fixture.config.evaluator_tests_digest = "0".repeat(64),
        }
        assert_eq!(fixture.run()["status"], "Quarantined", "case {case}");
        fixture.assert_baseline();
    }
}

#[test]
fn paths_symlinks_and_hardlinks_never_escape() {
    for path in ["../README.md", "/README.md", "nested/README.md"] {
        let mut fixture = Fixture::new();
        fixture.request.relative_path = path.into();
        assert_eq!(fixture.run()["status"], "Quarantined");
        fixture.assert_baseline();
    }
    for hard in [false, true] {
        let fixture = Fixture::new();
        let target = fixture.config.checkout_root.join("README.md");
        let external = fixture._root.path().join("external.md");
        fs::write(&external, BEFORE).unwrap();
        fs::remove_file(&target).unwrap();
        if hard {
            fs::hard_link(&external, &target).unwrap();
        } else {
            symlink(&external, &target).unwrap();
        }
        let output = fixture.invoke(None);
        if output.status.success() {
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_ne!(result["status"], "Applied");
        }
        assert_eq!(fs::read(external).unwrap(), BEFORE);
    }
}

#[test]
fn interrupted_process_restores_then_remains_frozen() {
    for failpoint in ["after-durable-intent", "after-replacement"] {
        let mut fixture = Fixture::new();
        let result = fixture.invoke(Some(failpoint));
        assert!(!result.status.success());
        // The child is reaped by output(). Cold recovery is operator-authorized;
        // the broker must never automatically steal an existing lock.
        fs::remove_file(fixture.config.state_dir.join("maintenance-state.lock")).unwrap();
        assert_eq!(fixture.run()["status"], "Frozen");
        fixture.assert_baseline();
        fixture.request.nonce = 2;
        fixture.request.request_id = "fresh-packet".into();
        assert_eq!(fixture.run()["status"], "Frozen");
        fixture.assert_baseline();
    }
}

#[test]
fn existing_lock_blocks_second_writer() {
    let fixture = Fixture::new();
    fs::write(
        fixture.config.state_dir.join("maintenance-state.lock"),
        b"operator-owned lock",
    )
    .unwrap();
    let output = fixture.invoke(None);
    assert!(!output.status.success());
    fixture.assert_baseline();
}

#[test]
fn cancellation_after_replacement_restores_baseline() {
    let fixture = Fixture::new();
    let output = fixture.invoke(Some("cancel-after-replacement"));
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "RolledBack");
    assert_eq!(result["rolled_back"], true);
    fixture.assert_baseline();
    fs::remove_file(&fixture.config.cancellation_file).unwrap();
    assert_eq!(fixture.run()["status"], "Quarantined");
    fixture.assert_baseline();
}

#[test]
fn recovery_cannot_redirect_intent_to_another_checkout() {
    let mut fixture = Fixture::new();
    assert!(!fixture
        .invoke(Some("after-durable-intent"))
        .status
        .success());
    fs::remove_file(fixture.config.state_dir.join("maintenance-state.lock")).unwrap();
    let other = fs::canonicalize(fixture._root.path())
        .unwrap()
        .join("other-checkout");
    fs::create_dir(&other).unwrap();
    mode(&other, 0o700);
    fs::write(other.join("README.md"), AFTER).unwrap();
    fixture.config.checkout_root = other.clone();
    let output = fixture.invoke(None);
    if output.status.success() {
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_ne!(result["status"], "Applied");
    }
    assert_eq!(fs::read(other.join("README.md")).unwrap(), AFTER);
}
