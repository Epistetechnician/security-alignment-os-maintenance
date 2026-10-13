//! Host-side runner for the fixed maintenance replication matrix.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module executes only the already frozen maintenance broker operation.
//! It creates isolated per-scenario checkouts, records raw local evidence, and
//! emits a signed [`HostReport`]. It does not authenticate a host or operator,
//! transfer evidence, contact a second host, or promote the result beyond the
//! replication contract's local `Inconclusive` ceiling.

use crate::maintenance_process::{
    checkout_baseline_digest, checkout_lock_path, fixed_input_digest, fixed_policy_digest,
    fixed_tests_digest, normalize_trailing_ascii_spaces, Config, Outcome, OutcomeStatus, Request,
    PROCESS_VERSION,
};
use crate::maintenance_replication::{
    baseline_manifest_digest, BaselineManifestEntry, HostReport, ManifestFileKind,
    RecoveryDisposition, ReplicationPacket, ScenarioResult, ScenarioRole, ScenarioStatus,
    FIXED_OPERATION_IDENTITY, REPLICATION_CLAIM_CEILING, REPLICATION_VERSION, REQUIRED_SCENARIOS,
};
use crate::{canonical_bytes, digest, digest_bytes, Error, Result, STATE_SLICE};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const RUNNER_VERSION: u8 = 1;
pub const FROZEN_REQUEST_ID: &str = "maintenance-replication-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FrozenBundle {
    pub version: u8,
    pub state_slice: String,
    pub operation: String,
    pub process_version: u8,
    pub request: Request,
    pub baseline_manifest: Vec<BaselineManifestEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunnerSpec {
    pub version: u8,
    pub state_slice: String,
    pub operation: String,
    pub process_version: u8,
    pub checkout_source: PathBuf,
    pub artifact_dir: PathBuf,
    pub maintenance_broker_path: PathBuf,
    pub evaluator_path: PathBuf,
    pub evaluator_seed_path: PathBuf,
    pub host_id: String,
    pub operator_id: String,
    pub host_seed_path: PathBuf,
    pub operator_seed_path: PathBuf,
    pub implementation_revision: String,
    pub evaluator_timeout_ms: u64,
    pub contention_role: ScenarioRole,
    pub frozen: FrozenBundle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct InvocationEvidence {
    exit_code: Option<i32>,
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ScenarioEvidence {
    version: u8,
    state_slice: String,
    scenario_id: String,
    role: ScenarioRole,
    request_digest: String,
    config_digest: String,
    initial_checkout_digest: String,
    final_checkout_digest: String,
    outside_target_digest: Option<String>,
    invocations: Vec<InvocationEvidence>,
}

struct Case {
    root: PathBuf,
    checkout: PathBuf,
    state: PathBuf,
    cancel: PathBuf,
    config_path: PathBuf,
    request_path: PathBuf,
    config: Config,
    request: Request,
}

#[derive(Clone, Debug)]
struct Invocation {
    output: Output,
}

impl Invocation {
    fn evidence(&self) -> InvocationEvidence {
        InvocationEvidence {
            exit_code: self.output.status.code(),
            success: self.output.status.success(),
            stdout: self.output.stdout.clone(),
            stderr: self.output.stderr.clone(),
        }
    }

    fn outcome(&self) -> Option<Outcome> {
        if !self.output.status.success() {
            return None;
        }
        serde_json::from_slice(&self.output.stdout).ok()
    }
}

fn now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| Error::Rejected("system clock is before Unix epoch".into()))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn mode_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::symlink_metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(Error::Rejected(format!(
                "runner path is not owner-only: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() {
            return Err(Error::Rejected(
                "runner artifact path is not a directory".into(),
            ));
        }
    } else {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    mode_owner_only(path)
}

fn ensure_private_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::Rejected(format!(
            "runner path is not a regular file: {}",
            path.display()
        )));
    }
    mode_owner_only(path)?;
    Ok(fs::read(path)?)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Rejected("runner output has no parent".into()))?;
    ensure_private_dir(parent)?;
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

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Rejected("runner output has no parent".into()))?;
    ensure_private_dir(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
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

fn read_canonical<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = ensure_private_file(path)?;
    let value = serde_json::from_slice(&bytes)?;
    if canonical_bytes(&value)? != bytes {
        return Err(Error::Rejected(format!(
            "runner input is not canonical JSON: {}",
            path.display()
        )));
    }
    Ok(value)
}

fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let bytes = ensure_private_file(path)?;
    if bytes.len() != 32 {
        return Err(Error::Rejected(
            "runner signing seed must be 32 bytes".into(),
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

pub fn load_frozen_bundle(path: &Path) -> Result<FrozenBundle> {
    let bundle: FrozenBundle = read_canonical(path)?;
    validate_frozen_bundle(&bundle)?;
    Ok(bundle)
}

pub fn load_runner_spec(path: &Path) -> Result<RunnerSpec> {
    let spec: RunnerSpec = read_canonical(path)?;
    validate_spec(&spec)?;
    Ok(spec)
}

pub fn load_host_report(path: &Path) -> Result<HostReport> {
    let report: HostReport = read_canonical(path)?;
    report.validate()?;
    Ok(report)
}

fn copy_checkout(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() {
        return Err(Error::Rejected(
            "runner source checkout is not a directory".into(),
        ));
    }
    ensure_private_dir(destination)?;
    for item in fs::read_dir(source)? {
        let item = item?;
        let source_path = item.path();
        let destination_path = destination.join(item.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Rejected(
                "runner source checkout contains a symlink".into(),
            ));
        }
        if metadata.is_dir() {
            copy_checkout(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::Rejected(
                        "runner source checkout contains a hardlink".into(),
                    ));
                }
            }
            fs::copy(&source_path, &destination_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&destination_path, fs::Permissions::from_mode(0o600))?;
            }
        } else {
            return Err(Error::Rejected(
                "runner source checkout contains a special file".into(),
            ));
        }
    }
    Ok(())
}

fn collect_manifest(
    root: &Path,
    current: &Path,
    entries: &mut Vec<BaselineManifestEntry>,
) -> Result<u64> {
    if current
        .strip_prefix(root)
        .map_or(usize::MAX, |path| path.components().count())
        > 32
    {
        return Err(Error::Rejected(
            "runner checkout depth exceeds limit".into(),
        ));
    }
    let mut total = 0_u64;
    for item in fs::read_dir(current)? {
        let item = item?;
        let path = item.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Rejected("runner checkout contains a symlink".into()));
        }
        if metadata.is_dir() {
            total = total
                .checked_add(collect_manifest(root, &path, entries)?)
                .ok_or_else(|| Error::Rejected("runner checkout manifest is too large".into()))?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::Rejected(
                        "runner checkout contains a hardlink".into(),
                    ));
                }
            }
            let bytes = fs::read(&path)?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::Rejected("runner checkout manifest is too large".into()))?;
            if entries.len() >= 4096 || total > 32 * 1024 * 1024 {
                return Err(Error::Rejected(
                    "runner checkout manifest is too large".into(),
                ));
            }
            let relative_path = path
                .strip_prefix(root)
                .map_err(|_| Error::Rejected("runner checkout path escaped".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push(BaselineManifestEntry {
                relative_path,
                byte_length: bytes.len() as u64,
                content_digest: digest_bytes(&bytes),
                file_kind: ManifestFileKind::Regular,
                link_count: 1,
            });
        } else {
            return Err(Error::Rejected(
                "runner checkout contains a special file".into(),
            ));
        }
    }
    Ok(total)
}

pub fn baseline_manifest(root: &Path) -> Result<Vec<BaselineManifestEntry>> {
    let mut entries = Vec::new();
    collect_manifest(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    crate::maintenance_replication::validate_baseline_manifest(&entries)?;
    Ok(entries)
}

fn target_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || !relative.ends_with(".md")
    {
        return Err(Error::Rejected("frozen request target is invalid".into()));
    }
    Ok(root.join(path))
}

pub fn freeze_checkout(
    checkout: &Path,
    request_id: &str,
    lease_expires_at: u64,
    nonce: u64,
) -> Result<FrozenBundle> {
    if !checkout.is_absolute() || !valid_text(request_id) || lease_expires_at == 0 || nonce == 0 {
        return Err(Error::Rejected("frozen request inputs are invalid".into()));
    }
    let checkout = fs::canonicalize(checkout)?;
    let baseline_manifest = baseline_manifest(&checkout)?;
    let baseline_digest = checkout_baseline_digest(&checkout)?;
    let target = target_path(&checkout, "README.md")?;
    let before_bytes = fs::read(&target)?;
    let after_bytes = normalize_trailing_ascii_spaces(&before_bytes);
    if before_bytes == after_bytes {
        return Err(Error::Rejected(
            "frozen checkout has no permitted change".into(),
        ));
    }
    let request = Request {
        request_id: request_id.into(),
        relative_path: "README.md".into(),
        before_digest: digest_bytes(&before_bytes),
        after_digest: digest_bytes(&after_bytes),
        before_bytes,
        after_bytes,
        checkout_baseline_digest: baseline_digest,
        lease_expires_at,
        nonce,
    };
    if request.lease_expires_at <= now_secs()? {
        return Err(Error::Rejected(
            "frozen request lease is already expired".into(),
        ));
    }
    let bundle = FrozenBundle {
        version: RUNNER_VERSION,
        state_slice: STATE_SLICE.into(),
        operation: FIXED_OPERATION_IDENTITY.into(),
        process_version: PROCESS_VERSION,
        request,
        baseline_manifest,
    };
    validate_frozen_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_frozen_bundle(bundle: &FrozenBundle) -> Result<()> {
    if bundle.version != RUNNER_VERSION
        || bundle.state_slice != STATE_SLICE
        || bundle.operation != FIXED_OPERATION_IDENTITY
        || bundle.process_version != PROCESS_VERSION
    {
        return Err(Error::Rejected("frozen bundle identity is invalid".into()));
    }
    crate::maintenance_process::validate_request(&bundle.request, 0)?;
    if normalize_trailing_ascii_spaces(&bundle.request.before_bytes) != bundle.request.after_bytes {
        return Err(Error::Rejected(
            "frozen request is not the fixed transformation".into(),
        ));
    }
    crate::maintenance_replication::validate_baseline_manifest(&bundle.baseline_manifest)?;
    Ok(())
}

fn expected(
    scenario_id: &str,
    role: ScenarioRole,
) -> Result<(ScenarioStatus, Option<ScenarioStatus>, RecoveryDisposition)> {
    let value = match scenario_id {
        "authorized-completion" => (
            ScenarioStatus::Applied,
            None,
            RecoveryDisposition::AuthorizedChangeCommitted,
        ),
        "replay-after-completion" => (
            ScenarioStatus::Quarantined,
            None,
            RecoveryDisposition::AlreadyAppliedPreserved,
        ),
        "invalid-or-stale-baseline"
        | "pre-admission-expiry"
        | "pre-admission-cancellation"
        | "evaluator-requirement-substitution"
        | "path-escape"
        | "evaluation-expiry" => (
            ScenarioStatus::Quarantined,
            None,
            RecoveryDisposition::NoMutation,
        ),
        "link-escape" => (
            ScenarioStatus::ProcessError,
            None,
            RecoveryDisposition::NoMutation,
        ),
        "pre-finalization-cancellation" | "pre-finalization-expiry" => (
            ScenarioStatus::RolledBack,
            None,
            RecoveryDisposition::BaselineRestored,
        ),
        "crash-after-durable-intent"
        | "crash-after-replacement"
        | "completion-state-persistence-failure" => (
            ScenarioStatus::ProcessError,
            Some(ScenarioStatus::Frozen),
            RecoveryDisposition::BaselineRestored,
        ),
        "concurrent-target-change" | "neighbor-change-recovery" => (
            ScenarioStatus::Frozen,
            None,
            RecoveryDisposition::ExternalChangePreservedAndFrozen,
        ),
        "occupied-lock" => (
            ScenarioStatus::ProcessError,
            None,
            RecoveryDisposition::NoMutation,
        ),
        "cross-state-directory-lock-contention" => match role {
            ScenarioRole::Winner => (
                ScenarioStatus::Applied,
                None,
                RecoveryDisposition::AuthorizedChangeCommitted,
            ),
            ScenarioRole::Contender => (
                ScenarioStatus::Blocked,
                None,
                RecoveryDisposition::NoMutation,
            ),
            ScenarioRole::Primary => {
                return Err(Error::Rejected(
                    "contention role must be winner or contender".into(),
                ))
            }
        },
        "replacement-lock-ownership" => (
            ScenarioStatus::Applied,
            None,
            RecoveryDisposition::AuthorizedChangeCommitted,
        ),
        "recovery-config-redirect" => (
            ScenarioStatus::ProcessError,
            None,
            RecoveryDisposition::AlternateCheckoutPreserved,
        ),
        _ => return Err(Error::Rejected("unknown replication scenario".into())),
    };
    Ok(value)
}

fn base_config(
    spec: &RunnerSpec,
    case: &Case,
    evaluator_digest: &str,
    evaluator_public_key: &str,
) -> Config {
    Config {
        evaluator_path: spec.evaluator_path.clone(),
        evaluator_seed_path: spec.evaluator_seed_path.clone(),
        evaluator_executable_digest: evaluator_digest.into(),
        evaluator_public_key: evaluator_public_key.into(),
        evaluator_input_digest: fixed_input_digest(),
        evaluator_tests_digest: fixed_tests_digest(),
        policy_digest: fixed_policy_digest(),
        checkout_root: case.checkout.clone(),
        state_dir: case.state.clone(),
        cancellation_file: case.cancel.clone(),
        evaluator_timeout_ms: spec.evaluator_timeout_ms,
    }
}

fn spawn_broker(
    broker: &Path,
    case: &Case,
    failpoint: Option<&str>,
    pause_ms: Option<u64>,
) -> Result<Child> {
    let mut command = Command::new(broker);
    command
        .arg(&case.config_path)
        .arg(&case.request_path)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = failpoint {
        command.env("MAINTENANCE_TEST_FAILPOINT", value);
    }
    if let Some(value) = pause_ms {
        command.env("MAINTENANCE_TEST_PAUSE_MS", value.to_string());
    }
    Ok(command.spawn()?)
}

fn invoke_broker(
    broker: &Path,
    case: &Case,
    failpoint: Option<&str>,
    pause_ms: Option<u64>,
) -> Result<Invocation> {
    let child = spawn_broker(broker, case, failpoint, pause_ms)?;
    Ok(Invocation {
        output: child.wait_with_output()?,
    })
}

fn write_case_inputs(case: &Case) -> Result<()> {
    write_private(&case.config_path, &canonical_bytes(&case.config)?)?;
    write_private(&case.request_path, &canonical_bytes(&case.request)?)
}

fn wait_for_path(path: &Path) -> Result<()> {
    for _ in 0..2_000 {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err(Error::Rejected(format!(
        "runner timed out waiting for {}",
        path.display()
    )))
}

fn wait_for_bytes(path: &Path, expected: &[u8]) -> Result<()> {
    for _ in 0..2_000 {
        if fs::read(path).ok().as_deref() == Some(expected) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err(Error::Rejected(format!(
        "runner timed out waiting for {}",
        path.display()
    )))
}

fn remove_owned_lock(root: &Path) -> Result<()> {
    let path = checkout_lock_path(root);
    if !path.exists() {
        return Err(Error::Rejected("runner expected a recovery lock".into()));
    }
    fs::remove_file(path)?;
    Ok(())
}

fn full_digest(root: &Path) -> Result<String> {
    checkout_baseline_digest(root)
}

fn scenario_case(spec: &RunnerSpec, scenario_id: &str, index: usize) -> Result<Case> {
    let root = spec
        .artifact_dir
        .join("cases")
        .join(format!("{index:02}-{scenario_id}"));
    ensure_private_dir(&root)?;
    let root = fs::canonicalize(root)?;
    let checkout = root.join("checkout");
    let state = root.join("state");
    ensure_private_dir(&state)?;
    copy_checkout(&spec.checkout_source, &checkout)?;
    let config_path = root.join("config.json");
    let request_path = root.join("request.json");
    let request = spec.frozen.request.clone();
    Ok(Case {
        root: root.clone(),
        checkout,
        state: state.clone(),
        cancel: root.join("cancel"),
        config_path,
        request_path,
        config: Config {
            evaluator_path: spec.evaluator_path.clone(),
            evaluator_seed_path: spec.evaluator_seed_path.clone(),
            evaluator_executable_digest: String::new(),
            evaluator_public_key: String::new(),
            evaluator_input_digest: fixed_input_digest(),
            evaluator_tests_digest: fixed_tests_digest(),
            policy_digest: fixed_policy_digest(),
            checkout_root: PathBuf::new(),
            state_dir: state.clone(),
            cancellation_file: root.join("cancel"),
            evaluator_timeout_ms: spec.evaluator_timeout_ms,
        },
        request,
    })
}

fn prepare_case(
    spec: &RunnerSpec,
    mut case: Case,
    evaluator_digest: &str,
    evaluator_key: &str,
) -> Result<Case> {
    case.config = base_config(spec, &case, evaluator_digest, evaluator_key);
    if case.config.checkout_root != case.checkout {
        return Err(Error::Rejected(
            "runner case checkout binding failed".into(),
        ));
    }
    write_case_inputs(&case)?;
    Ok(case)
}

#[allow(clippy::too_many_arguments)]
fn result_from(
    scenario_id: &str,
    role: ScenarioRole,
    request_digest: &str,
    config_digest: &str,
    initial: String,
    final_digest: String,
    outside_target_digest: Option<String>,
    invocations: Vec<Invocation>,
    status: ScenarioStatus,
    recovery_status: Option<ScenarioStatus>,
    recovery: RecoveryDisposition,
    evidence_dir: &Path,
) -> Result<ScenarioResult> {
    let evidence = ScenarioEvidence {
        version: RUNNER_VERSION,
        state_slice: STATE_SLICE.into(),
        scenario_id: scenario_id.into(),
        role,
        request_digest: request_digest.into(),
        config_digest: config_digest.into(),
        initial_checkout_digest: initial.clone(),
        final_checkout_digest: final_digest.clone(),
        outside_target_digest,
        invocations: invocations.iter().map(Invocation::evidence).collect(),
    };
    let bytes = canonical_bytes(&evidence)?;
    let evidence_path = evidence_dir.join(format!("{scenario_id}.json"));
    write_private(&evidence_path, &bytes)?;
    Ok(ScenarioResult {
        scenario_id: scenario_id.into(),
        role,
        status,
        recovery_status,
        recovery,
        initial_checkout_digest: initial,
        final_checkout_digest: final_digest,
        evidence_digest: digest_bytes(&bytes),
    })
}

fn expect_outcome(invocation: &Invocation, expected: OutcomeStatus) -> Result<()> {
    let outcome = invocation
        .outcome()
        .ok_or_else(|| Error::Rejected("runner expected a successful broker outcome".into()))?;
    if outcome.status != expected {
        return Err(Error::Rejected(format!(
            "runner outcome mismatch: expected {expected:?}, got {:?}; stdout={}; stderr={}",
            outcome.status,
            String::from_utf8_lossy(&invocation.output.stdout),
            String::from_utf8_lossy(&invocation.output.stderr)
        )));
    }
    Ok(())
}

fn expect_process_error(invocation: &Invocation) -> Result<()> {
    if invocation.output.status.success() {
        return Err(Error::Rejected(
            "runner expected a broker process error".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn make_case_result(
    spec: &RunnerSpec,
    case: &Case,
    scenario_id: &str,
    role: ScenarioRole,
    invocations: Vec<Invocation>,
    initial: String,
    final_digest: String,
    outside_target_digest: Option<String>,
) -> Result<ScenarioResult> {
    let (status, recovery_status, recovery) = expected(scenario_id, role)?;
    let first = invocations
        .first()
        .ok_or_else(|| Error::Rejected("runner scenario has no invocation".into()))?;
    let terminal = if status_is_recovery_terminal(status) && invocations.len() > 1 {
        invocations
            .last()
            .ok_or_else(|| Error::Rejected("runner scenario has no terminal invocation".into()))?
    } else {
        first
    };
    let check = match status {
        ScenarioStatus::Applied => expect_outcome(terminal, OutcomeStatus::Applied),
        ScenarioStatus::Quarantined => expect_outcome(terminal, OutcomeStatus::Quarantined),
        ScenarioStatus::RolledBack => expect_outcome(terminal, OutcomeStatus::RolledBack),
        ScenarioStatus::Frozen => expect_outcome(terminal, OutcomeStatus::Frozen),
        ScenarioStatus::ProcessError => expect_process_error(terminal),
        ScenarioStatus::Blocked => expect_process_error(terminal),
    };
    if let Err(error) = check {
        return Err(Error::Rejected(format!(
            "{error}; config={:?}",
            case.config
        )));
    }
    if let Some(expected_recovery) = recovery_status {
        let recovery_invocation = invocations
            .get(1)
            .ok_or_else(|| Error::Rejected("runner scenario has no recovery invocation".into()))?;
        expect_outcome(
            recovery_invocation,
            match expected_recovery {
                ScenarioStatus::Frozen => OutcomeStatus::Frozen,
                _ => return Err(Error::Rejected("unsupported runner recovery status".into())),
            },
        )?;
    }
    let request_digest = digest(&case.request)?;
    let config_digest = digest(&case.config)?;
    make_case_result_with_status(
        spec,
        scenario_id,
        role,
        invocations,
        initial,
        final_digest,
        outside_target_digest,
        status,
        recovery_status,
        recovery,
        &request_digest,
        &config_digest,
    )
}

fn status_is_recovery_terminal(status: ScenarioStatus) -> bool {
    matches!(status, ScenarioStatus::Frozen)
}

#[allow(clippy::too_many_arguments)]
fn make_case_result_with_status(
    spec: &RunnerSpec,
    scenario_id: &str,
    role: ScenarioRole,
    invocations: Vec<Invocation>,
    initial: String,
    final_digest: String,
    outside_target_digest: Option<String>,
    status: ScenarioStatus,
    recovery_status: Option<ScenarioStatus>,
    recovery: RecoveryDisposition,
    request_digest: &str,
    config_digest: &str,
) -> Result<ScenarioResult> {
    result_from(
        scenario_id,
        role,
        request_digest,
        config_digest,
        initial,
        final_digest,
        outside_target_digest,
        invocations,
        status,
        recovery_status,
        recovery,
        &spec.artifact_dir.join("evidence"),
    )
}

fn mutate_request(case: &mut Case, request: Request) -> Result<()> {
    case.request = request;
    write_case_inputs(case)
}

fn mutate_config(case: &mut Case, mutate: impl FnOnce(&mut Config)) -> Result<()> {
    mutate(&mut case.config);
    write_case_inputs(case)
}

fn chmod_state(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn run_scenario(
    spec: &RunnerSpec,
    evaluator_digest: &str,
    evaluator_key: &str,
    scenario_id: &str,
    index: usize,
) -> Result<ScenarioResult> {
    let mut case = scenario_case(spec, scenario_id, index)?;
    let baseline = spec.frozen.request.checkout_baseline_digest.clone();
    case = prepare_case(spec, case, evaluator_digest, evaluator_key)?;
    let initial = baseline.clone();
    match scenario_id {
        "authorized-completion" => {
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            let final_digest = full_digest(&case.checkout)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial,
                final_digest,
                None,
            )
        }
        "replay-after-completion" => {
            let first = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            expect_outcome(&first, OutcomeStatus::Applied)?;
            let after = full_digest(&case.checkout)?;
            let second = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            expect_outcome(&second, OutcomeStatus::Quarantined)?;
            let final_digest = full_digest(&case.checkout)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![second],
                after,
                final_digest,
                None,
            )
        }
        "invalid-or-stale-baseline" => {
            let mut request = case.request.clone();
            request.checkout_baseline_digest = "0".repeat(64);
            mutate_request(&mut case, request)?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "pre-admission-expiry" => {
            let mut request = case.request.clone();
            request.lease_expires_at = now_secs()?;
            mutate_request(&mut case, request)?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "pre-admission-cancellation" => {
            write_private(&case.cancel, b"operator cancellation")?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "evaluator-requirement-substitution" => {
            mutate_config(&mut case, |config| {
                config.evaluator_tests_digest = "0".repeat(64)
            })?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "path-escape" => {
            let mut request = case.request.clone();
            request.relative_path = "../README.md".into();
            mutate_request(&mut case, request)?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "link-escape" => {
            let target = case.checkout.join("README.md");
            let outside = case.root.join("outside.md");
            write_private(&outside, &case.request.before_bytes)?;
            fs::remove_file(&target)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside, &target)?;
            #[cfg(not(unix))]
            return Err(Error::Rejected("link scenario requires Unix".into()));
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            let outside_digest = digest_bytes(&fs::read(&outside)?);
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial,
                baseline,
                Some(outside_digest),
            )
        }
        "evaluation-expiry" => {
            let mut request = case.request.clone();
            request.lease_expires_at = now_secs()?.saturating_add(2);
            mutate_request(&mut case, request)?;
            let invocation = invoke_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("pause-during-evaluation"),
                Some(2_500),
            )?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "pre-finalization-cancellation" => {
            let invocation = invoke_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("cancel-after-replacement"),
                None,
            )?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "pre-finalization-expiry" => {
            let invocation = invoke_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("expire-before-finalization"),
                None,
            )?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "crash-after-durable-intent" | "crash-after-replacement" => {
            let failpoint = scenario_id
                .strip_prefix("crash-")
                .ok_or_else(|| Error::Rejected("runner crash scenario name is invalid".into()))?;
            let first = invoke_broker(&spec.maintenance_broker_path, &case, Some(failpoint), None)?;
            expect_process_error(&first)?;
            remove_owned_lock(&case.checkout)?;
            let recovery = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            let final_digest = full_digest(&case.checkout)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![first, recovery],
                initial,
                final_digest,
                None,
            )
        }
        "concurrent-target-change" => {
            let child = spawn_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("pause-before-finalization"),
                Some(500),
            )?;
            let target = case.checkout.join("README.md");
            wait_for_bytes(&target, &case.request.after_bytes)?;
            write_private(&target, b"concurrent target change\n")?;
            let invocation = Invocation {
                output: child.wait_with_output()?,
            };
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial,
                full_digest(&case.checkout)?,
                None,
            )
        }
        "completion-state-persistence-failure" => {
            let child = spawn_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("pause-before-finalization"),
                Some(500),
            )?;
            let target = case.checkout.join("README.md");
            wait_for_bytes(&target, &case.request.after_bytes)?;
            chmod_state(&case.state, 0o500)?;
            let first = Invocation {
                output: child.wait_with_output()?,
            };
            chmod_state(&case.state, 0o700)?;
            expect_process_error(&first)?;
            let recovery = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![first, recovery],
                initial,
                full_digest(&case.checkout)?,
                None,
            )
        }
        "neighbor-change-recovery" => {
            let first = invoke_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("after-durable-intent"),
                None,
            )?;
            expect_process_error(&first)?;
            remove_owned_lock(&case.checkout)?;
            write_private(&case.checkout.join("neighbor.txt"), b"concurrent change\n")?;
            let recovery = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![first, recovery],
                initial,
                full_digest(&case.checkout)?,
                None,
            )
        }
        "occupied-lock" => {
            let lock = checkout_lock_path(&case.checkout);
            write_private(&lock, b"operator-owned lock")?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            fs::remove_file(lock)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "replacement-lock-ownership" => {
            let child = spawn_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("hold-checkout-lock"),
                Some(300),
            )?;
            let lock = checkout_lock_path(&case.checkout);
            wait_for_path(&lock)?;
            fs::remove_file(&lock)?;
            write_private(&lock, b"replacement lock owner")?;
            let invocation = Invocation {
                output: child.wait_with_output()?,
            };
            let replacement = fs::read(&lock)?;
            if replacement != b"replacement lock owner" {
                return Err(Error::Rejected(
                    "runner replacement lock was not preserved".into(),
                ));
            }
            fs::remove_file(lock)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Winner,
                vec![invocation],
                initial.clone(),
                full_digest(&case.checkout)?,
                None,
            )
        }
        "cross-state-directory-lock-contention" => {
            let state_two = case.root.join("state-two");
            ensure_private_dir(&state_two)?;
            let mut contender = case.config.clone();
            contender.state_dir = state_two.clone();
            let contender_config_path = case.root.join("contender-config.json");
            let contender_request_path = case.root.join("contender-request.json");
            let contender_case = Case {
                root: case.root.clone(),
                checkout: case.checkout.clone(),
                state: state_two,
                cancel: case.cancel.clone(),
                config_path: contender_config_path,
                request_path: contender_request_path,
                config: contender,
                request: case.request.clone(),
            };
            write_case_inputs(&contender_case)?;
            let winner_child = spawn_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("hold-checkout-lock"),
                Some(500),
            )?;
            wait_for_path(&checkout_lock_path(&case.checkout))?;
            let contender_child =
                spawn_broker(&spec.maintenance_broker_path, &contender_case, None, None)?;
            let contender = Invocation {
                output: contender_child.wait_with_output()?,
            };
            let contender_final = full_digest(&case.checkout)?;
            let winner = Invocation {
                output: winner_child.wait_with_output()?,
            };
            let winner_final = full_digest(&case.checkout)?;
            let selected = match spec.contention_role {
                ScenarioRole::Winner => {
                    (vec![winner, contender], ScenarioRole::Winner, winner_final)
                }
                ScenarioRole::Contender => (
                    vec![contender, winner],
                    ScenarioRole::Contender,
                    contender_final,
                ),
                ScenarioRole::Primary => {
                    return Err(Error::Rejected("contention role is required".into()))
                }
            };
            make_case_result(
                spec,
                &case,
                scenario_id,
                selected.1,
                selected.0,
                initial,
                selected.2,
                None,
            )
        }
        "recovery-config-redirect" => {
            let first = invoke_broker(
                &spec.maintenance_broker_path,
                &case,
                Some("after-durable-intent"),
                None,
            )?;
            expect_process_error(&first)?;
            remove_owned_lock(&case.checkout)?;
            let alternate = case.root.join("alternate-checkout");
            copy_checkout(&spec.checkout_source, &alternate)?;
            write_private(&alternate.join("README.md"), &case.request.after_bytes)?;
            let alternate_initial = full_digest(&alternate)?;
            mutate_config(&mut case, |config| config.checkout_root = alternate.clone())?;
            let invocation = invoke_broker(&spec.maintenance_broker_path, &case, None, None)?;
            make_case_result(
                spec,
                &case,
                scenario_id,
                ScenarioRole::Primary,
                vec![invocation],
                alternate_initial.clone(),
                full_digest(&alternate)?,
                None,
            )
        }
        _ => Err(Error::Rejected("runner scenario is not implemented".into())),
    }
}

fn validate_spec(spec: &RunnerSpec) -> Result<()> {
    if spec.version != RUNNER_VERSION
        || spec.state_slice != STATE_SLICE
        || spec.operation != FIXED_OPERATION_IDENTITY
        || spec.process_version != PROCESS_VERSION
        || !spec.checkout_source.is_absolute()
        || !spec.artifact_dir.is_absolute()
        || !spec.maintenance_broker_path.is_absolute()
        || !spec.evaluator_path.is_absolute()
        || !spec.evaluator_seed_path.is_absolute()
        || !spec.host_seed_path.is_absolute()
        || !spec.operator_seed_path.is_absolute()
        || !valid_text(&spec.host_id)
        || !valid_text(&spec.operator_id)
        || spec.host_id == spec.operator_id
        || !valid_revision(&spec.implementation_revision)
        || spec.evaluator_timeout_ms == 0
        || spec.evaluator_timeout_ms > 60_000
        || !matches!(
            spec.contention_role,
            ScenarioRole::Winner | ScenarioRole::Contender
        )
    {
        return Err(Error::Rejected("runner specification is invalid".into()));
    }
    validate_frozen_bundle(&spec.frozen)
}

pub fn run_host(spec: &RunnerSpec) -> Result<HostReport> {
    validate_spec(spec)?;
    ensure_private_dir(&spec.artifact_dir)?;
    mode_owner_only(&spec.checkout_source)?;
    let source_baseline = checkout_baseline_digest(&spec.checkout_source)?;
    if source_baseline != spec.frozen.request.checkout_baseline_digest {
        return Err(Error::Rejected(
            "runner source checkout does not match frozen baseline".into(),
        ));
    }
    let source_manifest = baseline_manifest(&spec.checkout_source)?;
    if baseline_manifest_digest(&source_manifest)?
        != baseline_manifest_digest(&spec.frozen.baseline_manifest)?
    {
        return Err(Error::Rejected(
            "runner source checkout does not match frozen manifest".into(),
        ));
    }
    let evaluator_bytes = ensure_private_file(&spec.evaluator_path)?;
    let evaluator_digest = digest_bytes(&evaluator_bytes);
    let evaluator_seed = read_seed(&spec.evaluator_seed_path)?;
    let evaluator_key = SigningKey::from_bytes(&evaluator_seed)
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let host_seed = read_seed(&spec.host_seed_path)?;
    let operator_seed = read_seed(&spec.operator_seed_path)?;
    if host_seed == operator_seed || host_seed == evaluator_seed || operator_seed == evaluator_seed
    {
        return Err(Error::Rejected(
            "runner signing seeds must be distinct".into(),
        ));
    }
    let evidence_dir = spec.artifact_dir.join("evidence");
    ensure_private_dir(&evidence_dir)?;
    let mut scenarios = Vec::with_capacity(REQUIRED_SCENARIOS.len());
    for (index, scenario_id) in REQUIRED_SCENARIOS.iter().enumerate() {
        scenarios.push(
            run_scenario(spec, &evaluator_digest, &evaluator_key, scenario_id, index)
                .map_err(|error| Error::Rejected(format!("{scenario_id}: {error}")))?,
        );
    }
    let mut report = HostReport {
        version: REPLICATION_VERSION,
        state_slice: STATE_SLICE.into(),
        operation: FIXED_OPERATION_IDENTITY.into(),
        process_version: PROCESS_VERSION,
        implementation_revision: spec.implementation_revision.clone(),
        toolchain_digest: toolchain_digest()?,
        request_digest: digest(&spec.frozen.request)?,
        checkout_baseline_digest: spec.frozen.request.checkout_baseline_digest.clone(),
        baseline_manifest_digest: baseline_manifest_digest(&spec.frozen.baseline_manifest)?,
        evaluator_executable_digest: evaluator_digest,
        evaluator_input_digest: fixed_input_digest(),
        evaluator_tests_digest: fixed_tests_digest(),
        policy_digest: fixed_policy_digest(),
        evaluator_public_key: evaluator_key,
        evaluator_timeout_ms: spec.evaluator_timeout_ms,
        claim_ceiling: REPLICATION_CLAIM_CEILING.into(),
        host_id: spec.host_id.clone(),
        operator_id: spec.operator_id.clone(),
        host_public_key: String::new(),
        operator_public_key: String::new(),
        scenarios,
        report_id: String::new(),
        host_signature: String::new(),
        operator_signature: String::new(),
    };
    if let Err(error) = report.sign_with_seeds(host_seed, operator_seed) {
        let scenario_summary = report
            .scenarios
            .iter()
            .map(|scenario| {
                format!(
                    "{}={:?}/{:?}/{:?}",
                    scenario.scenario_id, scenario.role, scenario.status, scenario.recovery
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        return Err(Error::Rejected(format!(
            "host report validation failed: {error}; scenarios={scenario_summary}"
        )));
    }
    write_private(
        &spec.artifact_dir.join("report.json"),
        &canonical_bytes(&report)?,
    )?;
    Ok(report)
}

pub fn toolchain_digest() -> Result<String> {
    let output = Command::new("rustc").arg("-Vv").output()?;
    if !output.status.success() {
        return Err(Error::Rejected("rustc -Vv failed".into()));
    }
    Ok(digest_bytes(&output.stdout))
}

pub fn assemble_packet(
    bundle: &FrozenBundle,
    first: HostReport,
    second: HostReport,
) -> Result<ReplicationPacket> {
    validate_frozen_bundle(bundle)?;
    ReplicationPacket::from_bundle(
        bundle.request.clone(),
        bundle.baseline_manifest.clone(),
        vec![first, second],
    )
}

pub fn generate_seed_file(path: &Path, marker: u8) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::Rejected("runner seed path must be absolute".into()));
    }
    let mut seed = [0_u8; 32];
    #[cfg(unix)]
    {
        let _ = marker;
        let mut random = File::open("/dev/urandom")?;
        random.read_exact(&mut seed)?;
    }
    #[cfg(not(unix))]
    {
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = marker.wrapping_add(index as u8);
        }
    }
    if seed.iter().all(|byte| *byte == 0) {
        seed[0] = marker.max(1);
    }
    write_new_private(path, &seed)
}
