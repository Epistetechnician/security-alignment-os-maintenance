//! Fixed maintenance process checks. State slice: security-alignment-os-foundation-v1.
#![cfg(unix)]

use ed25519_dalek::SigningKey;
use security_alignment_os::digest_bytes;
use security_alignment_os::maintenance_process::{
    checkout_baseline_digest, checkout_lock_path, fixed_input_digest, fixed_policy_digest,
    fixed_tests_digest, Config, Request,
};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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
            evaluator_timeout_ms: 10_000,
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

    fn spawn_config(
        &self,
        config: &Config,
        config_path: &Path,
        request: &Request,
        request_path: &Path,
        failpoint: Option<&str>,
        pause_ms: Option<u64>,
    ) -> Child {
        fs::write(config_path, serde_json::to_vec(config).unwrap()).unwrap();
        mode(config_path, 0o600);
        fs::write(request_path, serde_json::to_vec(request).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_maintenance_broker"));
        command
            .arg(config_path)
            .arg(request_path)
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(value) = failpoint {
            command.env("MAINTENANCE_TEST_FAILPOINT", value);
        }
        if let Some(value) = pause_ms {
            command.env("MAINTENANCE_TEST_PAUSE_MS", value.to_string());
        }
        command.spawn().unwrap()
    }

    fn spawn(&self, failpoint: Option<&str>, pause_ms: Option<u64>) -> Child {
        self.spawn_config(
            &self.config,
            &self.config_path,
            &self.request,
            &self.request_path,
            failpoint,
            pause_ms,
        )
    }

    fn invoke_with(&self, failpoint: Option<&str>, pause_ms: Option<u64>) -> Output {
        self.spawn(failpoint, pause_ms).wait_with_output().unwrap()
    }

    fn invoke(&self, failpoint: Option<&str>) -> Output {
        self.invoke_with(failpoint, None)
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

fn wait_for_bytes(path: &Path, expected: &[u8]) {
    for _ in 0..1_000 {
        if fs::read(path).ok().as_deref() == Some(expected) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("timed out waiting for {}", path.display());
}

fn wait_for_path(path: &Path) {
    for _ in 0..1_000 {
        if path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("timed out waiting for {}", path.display());
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
        fs::remove_file(checkout_lock_path(&fixture.config.checkout_root)).unwrap();
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
        checkout_lock_path(&fixture.config.checkout_root),
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
    fs::remove_file(checkout_lock_path(&fixture.config.checkout_root)).unwrap();
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

#[test]
fn lease_expiry_during_evaluation_never_mutates() {
    let mut fixture = Fixture::new();
    fixture.request.lease_expires_at = now() + 2;
    fixture.config.evaluator_timeout_ms = 5_000;
    let output = fixture.invoke_with(Some("pause-during-evaluation"), Some(2_500));
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "Quarantined");
    fixture.assert_baseline();
}

#[test]
fn cancellation_immediately_before_finalization_rolls_back() {
    let fixture = Fixture::new();
    let child = fixture.spawn(Some("pause-before-finalization"), Some(500));
    let target = fixture.config.checkout_root.join("README.md");
    wait_for_bytes(&target, AFTER);
    fs::write(&fixture.config.cancellation_file, b"operator cancellation").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "RolledBack");
    assert_eq!(result["rolled_back"], true);
    fixture.assert_baseline();
}

#[test]
fn expiry_immediately_before_finalization_rolls_back() {
    let fixture = Fixture::new();
    let child = fixture.spawn(Some("expire-before-finalization"), Some(100));
    let target = fixture.config.checkout_root.join("README.md");
    wait_for_bytes(&target, AFTER);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "RolledBack");
    assert_eq!(result["rolled_back"], true);
    fixture.assert_baseline();
}

#[test]
fn rollback_preserves_a_concurrent_target_change() {
    let fixture = Fixture::new();
    let child = fixture.spawn(Some("pause-before-finalization"), Some(500));
    let target = fixture.config.checkout_root.join("README.md");
    wait_for_bytes(&target, AFTER);
    fs::write(&target, b"concurrent target change\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "Frozen");
    assert_eq!(result["rolled_back"], false);
    assert_eq!(fs::read(&target).unwrap(), b"concurrent target change\n");
}

#[test]
fn completion_state_failure_restores_before_returning_error() {
    let fixture = Fixture::new();
    let child = fixture.spawn(Some("pause-before-finalization"), Some(500));
    let target = fixture.config.checkout_root.join("README.md");
    wait_for_bytes(&target, AFTER);
    mode(&fixture.config.state_dir, 0o500);
    let output = child.wait_with_output().unwrap();
    mode(&fixture.config.state_dir, 0o700);
    assert!(!output.status.success());
    fixture.assert_baseline();
    assert_eq!(fixture.run()["status"], "Frozen");
    fixture.assert_baseline();
}

#[test]
fn recovery_detects_neighbor_change_before_reporting_rollback() {
    let fixture = Fixture::new();
    assert!(!fixture
        .invoke(Some("after-durable-intent"))
        .status
        .success());
    fs::remove_file(checkout_lock_path(&fixture.config.checkout_root)).unwrap();
    fs::write(
        fixture.config.checkout_root.join("neighbor.txt"),
        b"concurrent change\n",
    )
    .unwrap();
    let result = fixture.run();
    assert_eq!(result["status"], "Frozen");
    assert_eq!(result["rolled_back"], false);
    assert_eq!(
        fs::read(fixture.config.checkout_root.join("README.md")).unwrap(),
        BEFORE
    );
    assert_eq!(
        fs::read(fixture.config.checkout_root.join("neighbor.txt")).unwrap(),
        b"concurrent change\n"
    );
}

#[test]
fn distinct_state_directories_share_checkout_writer_fence() {
    let fixture = Fixture::new();
    let state_two = fixture._root.path().join("state-two");
    fs::create_dir(&state_two).unwrap();
    mode(&state_two, 0o700);
    let mut config_two = fixture.config.clone();
    config_two.state_dir = fs::canonicalize(&state_two).unwrap();
    let config_two_path = fixture._root.path().join("config-two.json");
    let request_two_path = fixture._root.path().join("request-two.json");

    let first = fixture.spawn(Some("hold-checkout-lock"), Some(500));
    wait_for_path(&checkout_lock_path(&fixture.config.checkout_root));
    let second = fixture.spawn_config(
        &config_two,
        &config_two_path,
        &fixture.request,
        &request_two_path,
        None,
        None,
    );
    let second_output = second.wait_with_output().unwrap();
    assert!(
        !second_output.status.success(),
        "second writer unexpectedly completed: stdout={} stderr={}",
        String::from_utf8_lossy(&second_output.stdout),
        String::from_utf8_lossy(&second_output.stderr)
    );
    let first_output = first.wait_with_output().unwrap();
    assert!(first_output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&first_output.stdout).unwrap()["status"],
        "Applied"
    );
    assert_eq!(
        fs::read(fixture.config.checkout_root.join("README.md")).unwrap(),
        AFTER
    );
}

#[test]
fn lock_release_does_not_remove_a_replacement_lock() {
    let fixture = Fixture::new();
    let lock = checkout_lock_path(&fixture.config.checkout_root);
    let child = fixture.spawn(Some("hold-checkout-lock"), Some(300));
    wait_for_path(&lock);
    fs::remove_file(&lock).unwrap();
    fs::write(&lock, b"replacement lock owner").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(fs::read(&lock).unwrap(), b"replacement lock owner");
}
