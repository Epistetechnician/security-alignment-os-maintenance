//! Transaction-bound multi-file maintenance checks.
//! State slice: security-alignment-os-foundation-v1.

use ed25519_dalek::SigningKey;
use security_alignment_os::maintenance_transaction::{
    active_checkout, load_receipt, reference_evaluator_input_digest,
    reference_evaluator_policy_digest, reference_evaluator_tests_digest,
    workspace_generation_digest, Config, EvaluationReceipt, FileChange, PatchRequest,
    PreparedCandidate, TransactionOutcome, TransactionStatus,
};
use security_alignment_os::{digest, digest_bytes};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(target_os = "linux")]
const EVALUATOR_ADDRESS_SPACE_LIMIT: Option<u64> =
    Some(security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES);
#[cfg(target_os = "macos")]
const EVALUATOR_ADDRESS_SPACE_LIMIT: Option<u64> = None;

fn private(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

struct Fixture {
    _root: TempDir,
    config: Config,
    request: PatchRequest,
    evaluator_path: PathBuf,
    seed_path: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::with_evaluator_timeout(5_000)
    }

    fn with_evaluator_timeout(evaluator_timeout_ms: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        private(root.path(), 0o700);
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        private(&source, 0o700);
        fs::create_dir(source.join("src")).unwrap();
        private(&source.join("src"), 0o700);
        fs::write(source.join("README.md"), b"before readme\n").unwrap();
        fs::write(source.join("src/lib.rs"), b"pub const VALUE: u8 = 1;\n").unwrap();
        fs::write(source.join("neighbor.txt"), b"leave me\n").unwrap();

        let workspace_path = root.path().join("managed-workspace");
        let initialized = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"))
            .arg("init")
            .arg(&source)
            .arg(&workspace_path)
            .env_clear()
            .output()
            .expect("launch managed workspace initialization");
        assert!(
            initialized.status.success(),
            "initialization failed: {}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let initialization: serde_json::Value =
            serde_json::from_slice(&initialized.stdout).unwrap();
        let workspace = PathBuf::from(initialization["workspace_root"].as_str().unwrap());
        let baseline = active_checkout(&workspace).expect("resolve active checkout");
        assert_eq!(
            initialization["baseline_digest"].as_str().unwrap(),
            workspace_generation_digest(&baseline).unwrap()
        );
        let evaluator_path = root.path().join("trusted-evaluator");
        fs::copy(
            env!("CARGO_BIN_EXE_maintenance_patch_evaluator"),
            &evaluator_path,
        )
        .unwrap();
        private(&evaluator_path, 0o700);
        let evaluator_path = fs::canonicalize(evaluator_path).unwrap();
        let seed_path = root.path().join("evaluator-seed");
        let seed = [39u8; 32];
        fs::write(&seed_path, seed).unwrap();
        private(&seed_path, 0o600);
        let public_key = SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let config = Config {
            workspace_root: workspace.clone(),
            evaluator_executable_path: evaluator_path.clone(),
            evaluator_executable_digest: digest_bytes(&fs::read(&evaluator_path).unwrap()),
            evaluator_public_key: public_key,
            evaluator_input_digest: reference_evaluator_input_digest(),
            evaluator_tests_digest: reference_evaluator_tests_digest(),
            policy_digest: reference_evaluator_policy_digest(),
            evaluator_timeout_ms,
            evaluator_max_address_space_bytes: EVALUATOR_ADDRESS_SPACE_LIMIT,
            cancellation_file: fs::canonicalize(root.path()).unwrap().join("cancel"),
            allowed_paths: vec!["README.md".into(), "src/lib.rs".into()],
            max_files: 8,
            max_total_bytes: 1024 * 1024,
        };
        let before_readme = b"before readme\n".to_vec();
        let after_readme = b"after readme\n".to_vec();
        let before_source = b"pub const VALUE: u8 = 1;\n".to_vec();
        let after_source = b"pub const VALUE: u8 = 2;\n".to_vec();
        let request = PatchRequest {
            transaction_id: "patch-transaction-1".into(),
            checkout_baseline_digest: workspace_generation_digest(&baseline).unwrap(),
            changes: vec![
                FileChange::new("README.md", before_readme, after_readme),
                FileChange::new("src/lib.rs", before_source, after_source),
            ],
            issued_at: now(),
            lease_expires_at: now() + 300,
            nonce: 1,
        };
        let config_path = root.path().join("transaction-config.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        private(&config_path, 0o600);
        Self {
            _root: root,
            config,
            request,
            evaluator_path,
            seed_path,
            config_path,
        }
    }

    fn prepare(&self) -> PreparedCandidate {
        self.prepare_request(&self.request)
            .unwrap_or_else(|output| {
                panic!(
                    "prepare failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
    }

    fn store_request(&self, request: &PatchRequest) -> PathBuf {
        let request_path = self
            ._root
            .path()
            .join(format!("patch-request-{}.json", request.nonce));
        fs::write(&request_path, serde_json::to_vec(request).unwrap()).unwrap();
        private(&request_path, 0o600);
        request_path
    }

    fn prepare_request(
        &self,
        request: &PatchRequest,
    ) -> Result<PreparedCandidate, std::process::Output> {
        let request_path = self.store_request(request);
        let output = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"))
            .arg(&self.config_path)
            .arg("prepare")
            .arg(request_path)
            .env_clear()
            .output()
            .expect("launch patch broker prepare");
        if output.status.success() {
            Ok(serde_json::from_slice(&output.stdout).unwrap())
        } else {
            Err(output)
        }
    }

    fn evaluate(&self, prepared: &PreparedCandidate) -> EvaluationReceipt {
        self.evaluate_request(&self.request, prepared)
            .unwrap_or_else(|output| {
                panic!(
                    "evaluator failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
    }

    fn evaluate_request(
        &self,
        request: &PatchRequest,
        prepared: &PreparedCandidate,
    ) -> Result<EvaluationReceipt, std::process::Output> {
        let request_path = self.store_request(request);
        let prepared_path = self
            ._root
            .path()
            .join(format!("prepared-candidate-{}.json", request.nonce));
        fs::write(&prepared_path, serde_json::to_vec(prepared).unwrap()).unwrap();
        private(&prepared_path, 0o600);
        let output = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"))
            .arg(&self.config_path)
            .arg("evaluate")
            .arg(request_path)
            .arg(prepared_path)
            .arg(&self.seed_path)
            .env_clear()
            .output()
            .expect("launch sandboxed evaluator broker command");
        if output.status.success() {
            Ok(serde_json::from_slice(&output.stdout).unwrap())
        } else {
            Err(output)
        }
    }

    fn commit(&self, receipt: &EvaluationReceipt) -> TransactionOutcome {
        let output = self.run_commit(&self.request, receipt, None);
        assert!(
            output.status.success(),
            "commit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn run_commit(
        &self,
        request: &PatchRequest,
        receipt: &EvaluationReceipt,
        failpoint: Option<&str>,
    ) -> std::process::Output {
        let receipt_path = self
            ._root
            .path()
            .join(format!("evaluation-receipt-{}.json", request.nonce));
        fs::write(&receipt_path, serde_json::to_vec(receipt).unwrap()).unwrap();
        private(&receipt_path, 0o600);
        let request_path = self.store_request(request);
        let mut command = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"));
        command
            .arg(&self.config_path)
            .arg("commit")
            .arg(request_path)
            .arg(receipt_path)
            .env_clear();
        if let Some(failpoint) = failpoint {
            command.env("PATCH_TRANSACTION_TEST_FAILPOINT", failpoint);
        }
        command.output().expect("launch patch broker commit")
    }

    fn recover(&self) -> Option<TransactionOutcome> {
        let output = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"))
            .arg(&self.config_path)
            .arg("recover")
            .env_clear()
            .output()
            .expect("launch patch broker recovery");
        assert!(
            output.status.success(),
            "recovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

#[test]
fn signed_evaluation_publishes_a_multi_file_patch_as_one_workspace_generation() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    assert_eq!(
        fs::read(old_checkout.join("README.md")).unwrap(),
        b"before readme\n"
    );
    let evaluation = fixture.evaluate(&prepared);
    let outcome = fixture.commit(&evaluation);

    assert_eq!(outcome.status, TransactionStatus::Applied);
    assert_eq!(outcome.applied_paths, vec!["README.md", "src/lib.rs"]);
    assert!(!outcome.durable_receipt_digest.is_empty());
    let active = active_checkout(&fixture.config.workspace_root).unwrap();
    assert_ne!(active, old_checkout);
    assert_eq!(
        fs::read(active.join("README.md")).unwrap(),
        b"after readme\n"
    );
    assert_eq!(
        fs::read(active.join("src/lib.rs")).unwrap(),
        b"pub const VALUE: u8 = 2;\n"
    );
    assert_eq!(
        fs::read(active.join("neighbor.txt")).unwrap(),
        b"leave me\n"
    );
    assert_eq!(
        fs::read(old_checkout.join("README.md")).unwrap(),
        b"before readme\n"
    );
}

#[test]
fn stale_baseline_and_out_of_allowlist_paths_are_rejected_before_preparation() {
    let fixture = Fixture::new();
    let baseline = active_checkout(&fixture.config.workspace_root).unwrap();

    let mut stale = fixture.request.clone();
    stale.checkout_baseline_digest = "0".repeat(64);
    let stale_result = fixture.prepare_request(&stale);
    assert!(stale_result.is_err());
    assert!(String::from_utf8_lossy(&stale_result.unwrap_err().stderr).contains("baseline"));

    let mut outside = fixture.request.clone();
    outside.changes = vec![FileChange::new(
        "neighbor.txt",
        b"leave me\n".to_vec(),
        b"changed\n".to_vec(),
    )];
    let outside_result = fixture.prepare_request(&outside);
    assert!(outside_result.is_err());
    assert!(String::from_utf8_lossy(&outside_result.unwrap_err().stderr).contains("allowlist"));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        baseline
    );
}

#[test]
fn evaluator_binary_substitution_is_rejected_by_the_broker() {
    let fixture = Fixture::new();
    let mut evaluator = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.evaluator_path)
        .unwrap();
    evaluator.write_all(b"substitution").unwrap();
    evaluator.sync_all().unwrap();

    let result = fixture.prepare_request(&fixture.request);
    assert!(result.is_err());
    assert!(
        String::from_utf8_lossy(&result.unwrap_err().stderr).contains("evaluator digest mismatch")
    );
    assert!(fixture.recover().is_none());
}

#[test]
fn evaluator_address_space_budget_is_bound_to_its_signed_receipt() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let mut receipt = fixture.evaluate(&prepared);
    let original_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    receipt.evaluator_max_address_space_bytes =
        if fixture.config.evaluator_max_address_space_bytes.is_some() {
            None
        } else {
            Some(security_alignment_os::sandbox::DEFAULT_ADDRESS_SPACE_LIMIT_BYTES)
        };
    let seed: [u8; 32] = fs::read(&fixture.seed_path).unwrap().try_into().unwrap();
    receipt.sign_with_seed(seed).unwrap();

    let result = fixture.run_commit(&fixture.request, &receipt, None);

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("evaluator receipt binding"));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        original_checkout
    );
    assert_eq!(
        fixture.recover().unwrap().status,
        TransactionStatus::RolledBack
    );
}

#[test]
fn evaluator_rejects_candidate_changes_outside_the_approved_patch() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let mut prepared = fixture.prepare();
    fs::write(prepared.candidate_root.join("neighbor.txt"), b"tampered\n").unwrap();
    prepared.candidate_digest = workspace_generation_digest(&prepared.candidate_root).unwrap();

    let result = fixture.evaluate_request(&fixture.request, &prepared);
    assert!(result.is_err());
    assert!(
        String::from_utf8_lossy(&result.unwrap_err().stderr).contains("outside the approved patch")
    );
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let recovered = fixture.recover().expect("prepared candidate recovery");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
}

#[test]
fn expired_evaluator_receipt_is_rejected_and_recovery_freezes_the_workspace() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let prepared = fixture.prepare();
    let mut evaluation = fixture.evaluate(&prepared);
    evaluation.expires_at = evaluation.evaluated_at;
    evaluation.sign_with_seed([39u8; 32]).unwrap();

    let output = fixture.run_commit(&fixture.request, &evaluation, None);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("receipt binding"));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );

    let recovered = fixture.recover().expect("expired evaluation recovery");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
    assert!(recovered.rolled_back);
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let mut next = fixture.request.clone();
    next.transaction_id = "after-expiry-recovery".into();
    next.nonce = 2;
    let rejected = fixture.prepare_request(&next);
    assert!(rejected.is_err());
    assert!(String::from_utf8_lossy(&rejected.unwrap_err().stderr).contains("frozen"));
}

#[test]
fn evaluator_timeout_terminates_the_sandboxed_process_and_recovery_rolls_back() {
    let fixture = Fixture::with_evaluator_timeout(1);
    let baseline = active_checkout(&fixture.config.workspace_root).unwrap();
    let prepared = fixture.prepare();

    let error = fixture
        .evaluate_request(&fixture.request, &prepared)
        .unwrap_err();
    assert!(String::from_utf8_lossy(&error.stderr).contains("wall-clock budget"));

    let recovered = fixture.recover().expect("interrupted evaluation recovers");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
    assert!(recovered.rolled_back);
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        baseline
    );
    assert!(fixture.prepare_request(&fixture.request).is_err());
}

#[test]
fn request_lease_expiry_after_evaluation_blocks_publication() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let mut request = fixture.request.clone();
    request.issued_at = now();
    request.lease_expires_at = request.issued_at + 30;
    let prepared = fixture.prepare_request(&request).unwrap();
    let evaluation = fixture.evaluate_request(&request, &prepared).unwrap();
    while now() < request.lease_expires_at {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let output = fixture.run_commit(&request, &evaluation, None);
    assert!(!output.status.success());
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let recovered = fixture.recover().expect("expired request lease recovery");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
    assert!(recovered.rolled_back);
}

#[test]
fn candidate_mutation_after_evaluation_is_rejected_before_publication() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let prepared = fixture.prepare();
    let evaluation = fixture.evaluate(&prepared);
    fs::write(prepared.candidate_root.join("README.md"), b"substituted\n").unwrap();

    let output = fixture.run_commit(&fixture.request, &evaluation, None);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("candidate"));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let recovered = fixture.recover().expect("changed candidate recovery");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
}

#[test]
fn changed_baseline_is_preserved_and_recovery_does_not_claim_rollback() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let prepared = fixture.prepare();
    let evaluation = fixture.evaluate(&prepared);
    fs::write(old_checkout.join("neighbor.txt"), b"concurrent change\n").unwrap();

    let output = fixture.run_commit(&fixture.request, &evaluation, None);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("baseline changed"));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let recovered = fixture.recover().expect("changed baseline recovery");
    assert_eq!(recovered.status, TransactionStatus::Frozen);
    assert!(!recovered.rolled_back);
    assert_eq!(
        fs::read(old_checkout.join("neighbor.txt")).unwrap(),
        b"concurrent change\n"
    );
}

#[test]
fn cancellation_prevents_publication_and_records_recovery() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let prepared = fixture.prepare();
    let evaluation = fixture.evaluate(&prepared);
    fs::write(&fixture.config.cancellation_file, b"cancel").unwrap();
    private(&fixture.config.cancellation_file, 0o600);

    let output = fixture.run_commit(&fixture.request, &evaluation, None);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cancelled"));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let recovered = fixture.recover().expect("cancelled transaction recovery");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
}

#[test]
fn crash_after_atomic_pointer_swap_is_rolled_back_and_durably_recorded() {
    let fixture = Fixture::new();
    let old_checkout = active_checkout(&fixture.config.workspace_root).unwrap();
    let prepared = fixture.prepare();
    let evaluation = fixture.evaluate(&prepared);

    let crashed = fixture.run_commit(&fixture.request, &evaluation, Some("after-pointer-swap"));
    assert_eq!(crashed.status.code(), Some(90));
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        prepared.candidate_root
    );

    let recovered = fixture.recover().expect("crashed transaction recovery");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
    assert!(recovered.rolled_back);
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        old_checkout
    );
    let persisted = load_receipt(&fixture.config, &fixture.request.digest().unwrap())
        .unwrap()
        .expect("durable recovery receipt");
    assert_eq!(persisted.status, TransactionStatus::RolledBack);
    assert_eq!(
        digest(&persisted).unwrap(),
        recovered.durable_receipt_digest
    );

    let mut next = fixture.request.clone();
    next.transaction_id = "after-crash-recovery".into();
    next.nonce = 2;
    assert!(fixture.prepare_request(&next).is_err());
}

#[test]
fn successful_transaction_rejects_replay_and_loads_its_durable_receipt() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let evaluation = fixture.evaluate(&prepared);
    let outcome = fixture.commit(&evaluation);

    let replay = fixture.run_commit(&fixture.request, &evaluation, None);
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("already completed"));
    let persisted = load_receipt(&fixture.config, &fixture.request.digest().unwrap())
        .unwrap()
        .expect("durable applied receipt");
    assert_eq!(persisted.status, TransactionStatus::Applied);
    assert_eq!(digest(&persisted).unwrap(), outcome.durable_receipt_digest);
}

#[test]
fn concurrent_preparers_are_fenced_to_one_in_flight_transaction() {
    let fixture = Fixture::new();
    let baseline = active_checkout(&fixture.config.workspace_root).unwrap();
    let mut second = fixture.request.clone();
    second.transaction_id = "competing-transaction".into();
    second.nonce = 2;
    let first_path = fixture.store_request(&fixture.request);
    let second_path = fixture.store_request(&second);
    let first = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"))
        .arg(&fixture.config_path)
        .arg("prepare")
        .arg(first_path)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_maintenance_patch_broker"))
        .arg(&fixture.config_path)
        .arg("prepare")
        .arg(second_path)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let first_output = first.wait_with_output().unwrap();
    let second_output = second.wait_with_output().unwrap();
    assert_ne!(
        first_output.status.success(),
        second_output.status.success()
    );
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        baseline
    );
    let recovered = fixture.recover().expect("competing writer cleanup");
    assert_eq!(recovered.status, TransactionStatus::RolledBack);
    assert_eq!(
        active_checkout(&fixture.config.workspace_root).unwrap(),
        baseline
    );
}
