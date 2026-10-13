//! Transaction-bound multi-file maintenance over immutable local workspace generations.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! A proposer may replace existing regular files only. A pinned evaluator
//! receipt binds the exact baseline, candidate generation, patch, policy, and
//! lease. Publication is one atomic symlink replacement; recovery restores the
//! prior generation after an interrupted publication. This local reference
//! does not authenticate the human or host behind the configured evaluator key.

use crate::persistence::save_atomic_snapshot_locked;
use crate::{canonical_bytes, digest, digest_bytes, valid_digest, Error, Result, STATE_SLICE};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROCESS_VERSION: u8 = 1;
pub const MAX_PATCH_FILES: usize = 128;
pub const MAX_PATCH_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PATCH_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_PATCH_REQUEST_JSON_BYTES: u64 = MAX_PATCH_TOTAL_BYTES * 5 + 1024 * 1024;
pub const MAX_EVALUATION_AGE_SECS: u64 = 10 * 60;
pub const MAX_EVALUATOR_TIMEOUT_MS: u64 = 60_000;
const MAX_COMPLETED_TRANSACTIONS: usize = 1024;
const MAX_STATE_BYTES: u64 = 96 * 1024 * 1024;
const MAX_GENERATION_FILES: usize = 4096;
const MAX_GENERATION_BYTES: u64 = 32 * 1024 * 1024;
const REFERENCE_EVALUATOR_INPUT_IDENTITY: &str = "immutable-candidate-generation-v1";
const REFERENCE_EVALUATOR_TEST_IDENTITIES: [&str; 4] = [
    "request-and-patch-binding",
    "candidate-generation-binding",
    "requested-file-output-bytes",
    "repeatable-generation-digest",
];
const REFERENCE_EVALUATOR_POLICY_IDENTITY: &str =
    "manifest-only-no-candidate-code-execution-macos-seatbelt-linux-landlock-namespaces-seccomp-address-space-time-bounded-v3";

pub fn reference_evaluator_input_digest() -> String {
    digest_bytes(REFERENCE_EVALUATOR_INPUT_IDENTITY.as_bytes())
}

pub fn reference_evaluator_tests_digest() -> String {
    digest_bytes(REFERENCE_EVALUATOR_TEST_IDENTITIES.join("\n").as_bytes())
}

pub fn reference_evaluator_policy_digest() -> String {
    digest_bytes(REFERENCE_EVALUATOR_POLICY_IDENTITY.as_bytes())
}

/// Operator-owned local transaction policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    /// Managed root containing `current`, `versions/`, and `control/`.
    pub workspace_root: PathBuf,
    /// Pinned evaluator executable; the candidate evaluator is run separately.
    pub evaluator_executable_path: PathBuf,
    pub evaluator_executable_digest: String,
    pub evaluator_public_key: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    /// Broker-enforced evaluator wall-clock budget, also bound into its receipt.
    pub evaluator_timeout_ms: u64,
    /// Maximum evaluator virtual address space, enforced by the host and bound
    /// into its signed receipt.
    pub evaluator_max_address_space_bytes: Option<u64>,
    /// Operator-controlled cancellation marker, outside the managed root.
    pub cancellation_file: PathBuf,
    /// Sorted, unique exact relative paths the transaction may replace.
    pub allowed_paths: Vec<String>,
    pub max_files: usize,
    pub max_total_bytes: u64,
}

/// One exact replacement of an existing regular file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileChange {
    pub relative_path: String,
    pub before_bytes: Vec<u8>,
    pub before_digest: String,
    pub after_bytes: Vec<u8>,
    pub after_digest: String,
}

impl FileChange {
    pub fn new(path: impl Into<String>, before: Vec<u8>, after: Vec<u8>) -> Self {
        Self {
            relative_path: path.into(),
            before_digest: digest_bytes(&before),
            after_digest: digest_bytes(&after),
            before_bytes: before,
            after_bytes: after,
        }
    }
}

/// Frozen proposal bytes and lifecycle bounds for one transaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchRequest {
    pub transaction_id: String,
    pub checkout_baseline_digest: String,
    /// Changes must be sorted by normalized relative path and unique.
    pub changes: Vec<FileChange>,
    pub issued_at: u64,
    pub lease_expires_at: u64,
    pub nonce: u64,
}

impl PatchRequest {
    pub fn digest(&self) -> Result<String> {
        digest(self)
    }

    pub fn patch_digest(&self) -> Result<String> {
        digest(&self.changes)
    }

    pub fn validate(&self, config: &Config, now: u64) -> Result<()> {
        if !valid_id(&self.transaction_id)
            || self.nonce == 0
            || self.issued_at > now
            || self.lease_expires_at <= now
            || self.lease_expires_at <= self.issued_at
            || self.lease_expires_at - self.issued_at > 24 * 60 * 60
            || !valid_digest(&self.checkout_baseline_digest)
            || self.changes.is_empty()
            || self.changes.len() > config.max_files
            || self.changes.len() > MAX_PATCH_FILES
        {
            return Err(Error::Rejected(
                "patch transaction request is invalid".into(),
            ));
        }
        let mut total_bytes = 0u64;
        let mut previous_path: Option<&str> = None;
        for change in &self.changes {
            validate_relative_path(&change.relative_path)?;
            if config
                .allowed_paths
                .binary_search(&change.relative_path)
                .is_err()
            {
                return Err(Error::Rejected(
                    "patch path is outside the operator allowlist".into(),
                ));
            }
            if previous_path.is_some_and(|previous| previous >= change.relative_path.as_str()) {
                return Err(Error::Rejected(
                    "patch paths must be sorted and unique".into(),
                ));
            }
            previous_path = Some(&change.relative_path);
            if change.before_bytes == change.after_bytes
                || change.before_bytes.len() > MAX_PATCH_FILE_BYTES
                || change.after_bytes.len() > MAX_PATCH_FILE_BYTES
                || !valid_digest(&change.before_digest)
                || !valid_digest(&change.after_digest)
                || change.before_digest != digest_bytes(&change.before_bytes)
                || change.after_digest != digest_bytes(&change.after_bytes)
            {
                return Err(Error::Rejected(
                    "patch file bytes or digests are invalid".into(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(change.before_bytes.len() as u64)
                .and_then(|sum| sum.checked_add(change.after_bytes.len() as u64))
                .ok_or_else(|| Error::Rejected("patch size overflow".into()))?;
        }
        if total_bytes > config.max_total_bytes || total_bytes > MAX_PATCH_TOTAL_BYTES {
            return Err(Error::Rejected(
                "patch exceeds configured byte limit".into(),
            ));
        }
        Ok(())
    }
}

/// Candidate location and immutable content identity returned by prepare.
/// The path is a local operator-side value and is not included in a receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedCandidate {
    pub transaction_digest: String,
    pub candidate_digest: String,
    pub candidate_root: PathBuf,
}

#[derive(Clone, Serialize)]
struct GenerationEntry {
    relative_path: String,
    kind: &'static str,
    mode: u32,
    byte_len: u64,
    content_digest: Option<String>,
}

/// Input supplied to the pinned evaluator process after candidate preparation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvaluationJob {
    pub state_slice: String,
    pub request: PatchRequest,
    pub workspace_root: PathBuf,
    pub candidate_root: PathBuf,
    pub transaction_digest: String,
    pub patch_digest: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub allowed_paths: Vec<String>,
    pub allowed_paths_digest: String,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub evaluator_timeout_ms: u64,
    pub evaluator_max_address_space_bytes: Option<u64>,
    /// Digest of the broker-generated evaluator launch token.
    pub launch_token_digest: String,
    pub evaluated_at: u64,
    pub expires_at: u64,
}

impl EvaluationJob {
    pub fn new(
        config: &Config,
        request: &PatchRequest,
        prepared: &PreparedCandidate,
        launch_token_digest: &str,
    ) -> Result<Self> {
        let now = now_secs()?;
        validate_config(config)?;
        request.validate(config, now)?;
        let transaction_digest = request.digest()?;
        if transaction_digest != prepared.transaction_digest {
            return Err(Error::Rejected(
                "prepared candidate transaction mismatch".into(),
            ));
        }
        let actual_candidate_digest = workspace_generation_digest(&prepared.candidate_root)?;
        if actual_candidate_digest != prepared.candidate_digest {
            return Err(Error::Rejected(
                "prepared candidate changed before evaluation".into(),
            ));
        }
        if !valid_digest(launch_token_digest) {
            return Err(Error::Rejected(
                "evaluator launch token digest is invalid".into(),
            ));
        }
        Ok(Self {
            state_slice: STATE_SLICE.into(),
            request: request.clone(),
            workspace_root: config.workspace_root.clone(),
            candidate_root: prepared.candidate_root.clone(),
            transaction_digest,
            patch_digest: request.patch_digest()?,
            baseline_digest: request.checkout_baseline_digest.clone(),
            candidate_digest: prepared.candidate_digest.clone(),
            evaluator_executable_digest: config.evaluator_executable_digest.clone(),
            evaluator_input_digest: config.evaluator_input_digest.clone(),
            evaluator_tests_digest: config.evaluator_tests_digest.clone(),
            policy_digest: config.policy_digest.clone(),
            allowed_paths: config.allowed_paths.clone(),
            allowed_paths_digest: digest(&config.allowed_paths)?,
            max_files: config.max_files,
            max_total_bytes: config.max_total_bytes,
            evaluator_timeout_ms: config.evaluator_timeout_ms,
            evaluator_max_address_space_bytes: config.evaluator_max_address_space_bytes,
            launch_token_digest: launch_token_digest.to_owned(),
            evaluated_at: now,
            expires_at: request
                .lease_expires_at
                .min(now.saturating_add(MAX_EVALUATION_AGE_SECS)),
        })
    }
}

/// Signed acceptance of a specific candidate generation by the configured evaluator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationReceipt {
    pub state_slice: String,
    pub transaction_digest: String,
    pub patch_digest: String,
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub nonce: u64,
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub allowed_paths_digest: String,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub evaluator_timeout_ms: u64,
    pub evaluator_max_address_space_bytes: Option<u64>,
    pub evaluated_at: u64,
    pub expires_at: u64,
    pub accepted: bool,
    pub signature: String,
}

impl EvaluationReceipt {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&EvaluationReceiptUnsigned {
            state_slice: &self.state_slice,
            transaction_digest: &self.transaction_digest,
            patch_digest: &self.patch_digest,
            baseline_digest: &self.baseline_digest,
            candidate_digest: &self.candidate_digest,
            nonce: self.nonce,
            evaluator_executable_digest: &self.evaluator_executable_digest,
            evaluator_input_digest: &self.evaluator_input_digest,
            evaluator_tests_digest: &self.evaluator_tests_digest,
            policy_digest: &self.policy_digest,
            allowed_paths_digest: &self.allowed_paths_digest,
            max_files: self.max_files,
            max_total_bytes: self.max_total_bytes,
            evaluator_timeout_ms: self.evaluator_timeout_ms,
            evaluator_max_address_space_bytes: self.evaluator_max_address_space_bytes,
            evaluated_at: self.evaluated_at,
            expires_at: self.expires_at,
            accepted: self.accepted,
        })
    }

    pub fn sign_with_seed(&mut self, seed: [u8; 32]) -> Result<()> {
        self.signature = hex_encode(
            &SigningKey::from_bytes(&seed)
                .sign(&self.unsigned_bytes()?)
                .to_bytes(),
        );
        Ok(())
    }

    pub fn verify(&self, public_key_hex: &str) -> Result<()> {
        let key = decode_fixed::<32>(public_key_hex)?;
        let signature = decode_fixed::<64>(&self.signature)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| Error::Rejected("evaluator public key is invalid".into()))?
            .verify(&self.unsigned_bytes()?, &Signature::from_bytes(&signature))
            .map_err(|_| Error::Rejected("evaluator receipt signature is invalid".into()))
    }
}

#[derive(Serialize)]
struct EvaluationReceiptUnsigned<'a> {
    state_slice: &'a str,
    transaction_digest: &'a str,
    patch_digest: &'a str,
    baseline_digest: &'a str,
    candidate_digest: &'a str,
    nonce: u64,
    evaluator_executable_digest: &'a str,
    evaluator_input_digest: &'a str,
    evaluator_tests_digest: &'a str,
    policy_digest: &'a str,
    allowed_paths_digest: &'a str,
    max_files: usize,
    max_total_bytes: u64,
    evaluator_timeout_ms: u64,
    evaluator_max_address_space_bytes: Option<u64>,
    evaluated_at: u64,
    expires_at: u64,
    accepted: bool,
}

/// Verified evaluator result for the structural reference evaluator.
pub fn evaluate_job(job: &EvaluationJob) -> Result<EvaluationReceipt> {
    let now = now_secs()?;
    if job.max_files == 0
        || job.max_files > MAX_PATCH_FILES
        || job.max_total_bytes == 0
        || job.max_total_bytes > MAX_PATCH_TOTAL_BYTES
        || job.evaluator_timeout_ms == 0
        || job.evaluator_timeout_ms > MAX_EVALUATOR_TIMEOUT_MS
        || !address_space_policy_valid(job.evaluator_max_address_space_bytes)
        || !valid_digest(&job.launch_token_digest)
    {
        return Err(Error::Rejected(
            "evaluation resource limits are invalid".into(),
        ));
    }
    validate_allowed_paths(&job.allowed_paths)?;
    let evaluation_config = Config {
        workspace_root: PathBuf::from("/"),
        evaluator_executable_path: PathBuf::from("/"),
        evaluator_executable_digest: job.evaluator_executable_digest.clone(),
        evaluator_public_key: String::new(),
        evaluator_input_digest: job.evaluator_input_digest.clone(),
        evaluator_tests_digest: job.evaluator_tests_digest.clone(),
        policy_digest: job.policy_digest.clone(),
        evaluator_timeout_ms: job.evaluator_timeout_ms,
        evaluator_max_address_space_bytes: job.evaluator_max_address_space_bytes,
        cancellation_file: PathBuf::from("/"),
        allowed_paths: job.allowed_paths.clone(),
        max_files: job.max_files,
        max_total_bytes: job.max_total_bytes,
    };
    job.request.validate(&evaluation_config, now)?;
    if job.state_slice != STATE_SLICE
        || job.transaction_digest != job.request.digest()?
        || job.patch_digest != job.request.patch_digest()?
        || job.baseline_digest != job.request.checkout_baseline_digest
        || !valid_digest(&job.candidate_digest)
        || !valid_digest(&job.evaluator_executable_digest)
        || !valid_digest(&job.evaluator_input_digest)
        || !valid_digest(&job.evaluator_tests_digest)
        || !valid_digest(&job.policy_digest)
        || !valid_digest(&job.allowed_paths_digest)
        || job.evaluator_input_digest != reference_evaluator_input_digest()
        || job.evaluator_tests_digest != reference_evaluator_tests_digest()
        || job.policy_digest != reference_evaluator_policy_digest()
        || job.allowed_paths != sorted_unique_paths(&job.allowed_paths)
        || job.allowed_paths_digest != digest(&job.allowed_paths)?
        || job.evaluated_at > now
        || job.evaluated_at < job.request.issued_at
        || job.expires_at <= job.evaluated_at
        || job.expires_at <= now
        || job.expires_at > job.request.lease_expires_at
        || job.expires_at - job.evaluated_at > MAX_EVALUATION_AGE_SECS
    {
        return Err(Error::Rejected(
            "evaluation job binding is invalid or expired".into(),
        ));
    }
    let workspace_root = fs::canonicalize(&job.workspace_root)?;
    private_owned(&workspace_root, true)?;
    if workspace_root != job.workspace_root {
        return Err(Error::Rejected(
            "evaluation workspace path is not canonical".into(),
        ));
    }
    let versions = fs::canonicalize(workspace_root.join("versions"))?;
    let candidate_root = fs::canonicalize(&job.candidate_root)?;
    if candidate_root.parent() != Some(versions.as_path())
        || workspace_generation_digest(&candidate_root)? != job.candidate_digest
    {
        return Err(Error::Rejected(
            "candidate generation is outside the workspace or digest-mismatched".into(),
        ));
    }
    let baseline_root = active_checkout(&workspace_root)?;
    if workspace_generation_digest(&baseline_root)? != job.baseline_digest {
        return Err(Error::Rejected(
            "trusted baseline changed during evaluation".into(),
        ));
    }
    if expected_candidate_digest(&baseline_root, &job.request.changes)? != job.candidate_digest {
        return Err(Error::Rejected(
            "candidate contains changes outside the approved patch".into(),
        ));
    }
    for change in &job.request.changes {
        let target = candidate_root.join(&change.relative_path);
        let metadata = fs::symlink_metadata(&target)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Rejected(
                "candidate output is not a regular file".into(),
            ));
        }
        if read_regular_file_stable(&target, &metadata)? != change.after_bytes {
            return Err(Error::Rejected("candidate output bytes mismatch".into()));
        }
    }
    if workspace_generation_digest(&baseline_root)? != job.baseline_digest
        || workspace_generation_digest(&candidate_root)? != job.candidate_digest
    {
        return Err(Error::Rejected(
            "workspace changed during candidate evaluation".into(),
        ));
    }
    Ok(EvaluationReceipt {
        state_slice: job.state_slice.clone(),
        transaction_digest: job.transaction_digest.clone(),
        patch_digest: job.patch_digest.clone(),
        baseline_digest: job.baseline_digest.clone(),
        candidate_digest: job.candidate_digest.clone(),
        nonce: job.request.nonce,
        evaluator_executable_digest: job.evaluator_executable_digest.clone(),
        evaluator_input_digest: job.evaluator_input_digest.clone(),
        evaluator_tests_digest: job.evaluator_tests_digest.clone(),
        policy_digest: job.policy_digest.clone(),
        allowed_paths_digest: job.allowed_paths_digest.clone(),
        max_files: job.max_files,
        max_total_bytes: job.max_total_bytes,
        evaluator_timeout_ms: job.evaluator_timeout_ms,
        evaluator_max_address_space_bytes: job.evaluator_max_address_space_bytes,
        evaluated_at: job.evaluated_at,
        expires_at: job.expires_at,
        accepted: true,
        signature: String::new(),
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionStatus {
    Applied,
    Rejected,
    RolledBack,
    Frozen,
}

/// Persisted terminal receipt body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionReceipt {
    pub state_slice: String,
    pub status: TransactionStatus,
    pub transaction_id: String,
    pub request_digest: String,
    pub evaluator_receipt_digest: Option<String>,
    pub before_workspace_digest: String,
    pub after_workspace_digest: Option<String>,
    pub applied_paths: Vec<String>,
    pub completed_at: u64,
    pub rolled_back: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionOutcome {
    pub status: TransactionStatus,
    pub transaction_digest: String,
    pub durable_receipt_digest: String,
    pub applied_paths: Vec<String>,
    pub rolled_back: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableState {
    version: u8,
    config_digest: String,
    frozen: bool,
    used_nonces: BTreeSet<u64>,
    in_flight: Option<Intent>,
    completed: BTreeMap<String, TransactionReceipt>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Intent {
    transaction_id: String,
    request_digest: String,
    nonce: u64,
    baseline_digest: String,
    old_version: String,
    candidate_version: String,
    candidate_digest: Option<String>,
    phase: IntentPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum IntentPhase {
    Preparing,
    Prepared,
    CommitStarted,
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Rejected("system clock is before Unix epoch".into()))?
        .as_secs())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Rejected("hex field has wrong length".into()));
    }
    let mut output = [0; N];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::Rejected("hex field is malformed".into()))?;
    }
    Ok(output)
}

fn validate_relative_path(relative: &str) -> Result<()> {
    let components: Vec<_> = Path::new(relative).components().collect();
    let normalized = components
        .iter()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if relative.is_empty()
        || relative.len() > 512
        || relative.contains('\\')
        || relative.contains(':')
        || relative.chars().any(char::is_control)
        || components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || normalized != relative
        || relative
            .split('/')
            .any(|component| component.eq_ignore_ascii_case(".git"))
    {
        return Err(Error::Rejected("patch path is not safely relative".into()));
    }
    Ok(())
}

fn sorted_unique_paths(paths: &[String]) -> Vec<String> {
    let mut sorted = paths.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}

fn validate_allowed_paths(paths: &[String]) -> Result<()> {
    if paths.is_empty() || paths.len() > MAX_GENERATION_FILES {
        return Err(Error::Rejected("allowed path policy is invalid".into()));
    }
    let mut previous: Option<&str> = None;
    for path in paths {
        validate_relative_path(path)?;
        if previous.is_some_and(|previous| previous >= path.as_str()) {
            return Err(Error::Rejected(
                "allowed paths must be sorted and unique".into(),
            ));
        }
        previous = Some(path);
    }
    Ok(())
}

fn private_owned(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(Error::Rejected(
            "transaction path has an unsafe type".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Error::Rejected("transaction path is not owner-only".into()));
        }
    }
    Ok(())
}

fn canonical_file_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Rejected("control file has no parent".into()))?;
    let parent = fs::canonicalize(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::Rejected("control file name is invalid".into()))?;
    Ok(parent.join(name))
}

fn validate_config_base(config: &Config) -> Result<()> {
    if !config.workspace_root.is_absolute()
        || !config.evaluator_executable_path.is_absolute()
        || !config.cancellation_file.is_absolute()
        || !valid_digest(&config.evaluator_executable_digest)
        || !valid_digest(&config.evaluator_input_digest)
        || !valid_digest(&config.evaluator_tests_digest)
        || !valid_digest(&config.policy_digest)
        || decode_fixed::<32>(&config.evaluator_public_key).is_err()
        || config.max_files == 0
        || config.max_files > MAX_PATCH_FILES
        || config.max_total_bytes == 0
        || config.max_total_bytes > MAX_PATCH_TOTAL_BYTES
        || config.evaluator_timeout_ms == 0
        || config.evaluator_timeout_ms > MAX_EVALUATOR_TIMEOUT_MS
        || !address_space_policy_valid(config.evaluator_max_address_space_bytes)
    {
        return Err(Error::Rejected(
            "transaction configuration is invalid".into(),
        ));
    }
    validate_allowed_paths(&config.allowed_paths)?;
    private_owned(&config.workspace_root, true)?;
    let evaluator_path = canonical_file_path(&config.evaluator_executable_path)?;
    let cancellation_path = canonical_file_path(&config.cancellation_file)?;
    if evaluator_path.starts_with(&config.workspace_root)
        || cancellation_path.starts_with(&config.workspace_root)
    {
        return Err(Error::Rejected(
            "transaction control path overlaps workspace".into(),
        ));
    }
    if fs::canonicalize(&config.workspace_root)? != config.workspace_root {
        return Err(Error::Rejected("workspace root is not canonical".into()));
    }
    private_owned(&config.workspace_root.join("versions"), true)?;
    private_owned(&config.workspace_root.join("control"), true)?;
    Ok(())
}

fn address_space_policy_valid(value: Option<u64>) -> bool {
    #[cfg(target_os = "linux")]
    {
        value.is_some_and(|limit| {
            (crate::sandbox::MIN_ADDRESS_SPACE_LIMIT_BYTES
                ..=crate::sandbox::MAX_ADDRESS_SPACE_LIMIT_BYTES)
                .contains(&limit)
        })
    }
    #[cfg(target_os = "macos")]
    {
        value.is_none()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = value;
        false
    }
}

fn validate_config(config: &Config) -> Result<()> {
    validate_config_base(config)?;
    private_owned(&config.evaluator_executable_path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&config.evaluator_executable_path)?
            .permissions()
            .mode()
            & 0o100
            == 0
        {
            return Err(Error::Rejected("pinned evaluator is not executable".into()));
        }
    }
    if fs::canonicalize(&config.evaluator_executable_path)? != config.evaluator_executable_path {
        return Err(Error::Rejected(
            "evaluator executable path is not canonical".into(),
        ));
    }
    if digest_bytes(&fs::read(&config.evaluator_executable_path)?)
        != config.evaluator_executable_digest
    {
        return Err(Error::Rejected("pinned evaluator digest mismatch".into()));
    }
    Ok(())
}

fn cancellation_requested(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Create a managed immutable generation from a private source snapshot.
/// Existing Git metadata is rejected; initialize from a source-only export.
pub fn initialize_workspace(source: &Path, workspace_root: &Path) -> Result<()> {
    let source = fs::canonicalize(source)?;
    private_owned(&source, true)?;
    if !workspace_root.is_absolute() {
        return Err(Error::Rejected(
            "managed workspace path must be absolute".into(),
        ));
    }
    let parent = workspace_root
        .parent()
        .ok_or_else(|| Error::Rejected("managed workspace has no parent".into()))?;
    let parent = fs::canonicalize(parent)?;
    let name = workspace_root
        .file_name()
        .ok_or_else(|| Error::Rejected("managed workspace name is invalid".into()))?;
    let destination = parent.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(Error::Rejected("managed workspace already exists".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let initial_source_digest = workspace_generation_digest(&source)?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Rejected("system clock is before Unix epoch".into()))?
        .as_nanos();
    let staging = parent.join(format!(
        ".maintenance-init-{}-{}",
        std::process::id(),
        unique
    ));
    fs::create_dir(&staging)?;
    set_directory_private(&staging)?;
    let initialized = (|| -> Result<()> {
        let versions = staging.join("versions");
        let control = staging.join("control");
        fs::create_dir(&versions)?;
        set_directory_private(&versions)?;
        fs::create_dir(&control)?;
        set_directory_private(&control)?;
        let initial_name = "generation-0000000000000000";
        let initial = versions.join(initial_name);
        fs::create_dir(&initial)?;
        set_directory_private(&initial)?;
        copy_tree(&source, &initial, &mut 0, &mut 0)?;
        if workspace_generation_digest(&source)? != initial_source_digest {
            return Err(Error::Rejected(
                "source snapshot changed during initialization".into(),
            ));
        }
        let _ = workspace_generation_digest(&initial)?;
        File::open(&versions)?.sync_all()?;
        File::open(&staging)?.sync_all()?;
        create_active_link(&staging, &format!("versions/{initial_name}"))?;
        fs::rename(&staging, &destination)?;
        File::open(&parent)?.sync_all()?;
        Ok(())
    })();
    if initialized.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    initialized
}

fn set_directory_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn copy_tree(source: &Path, target: &Path, total: &mut u64, count: &mut usize) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Rejected("source snapshot contains a symlink".into()));
        }
        if metadata.is_dir() {
            if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(".git")
            {
                return Err(Error::Rejected(
                    "source snapshot contains Git metadata".into(),
                ));
            }
            fs::create_dir(&target_path)?;
            set_directory_private(&target_path)?;
            copy_tree(&source_path, &target_path, total, count)?;
        } else if metadata.is_file() {
            *count = count
                .checked_add(1)
                .ok_or_else(|| Error::Rejected("source file count overflow".into()))?;
            if *count > MAX_GENERATION_FILES {
                return Err(Error::Rejected("source snapshot has too many files".into()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::Rejected(
                        "source snapshot contains a hard link".into(),
                    ));
                }
            }
            if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(".git")
            {
                return Err(Error::Rejected(
                    "source snapshot contains Git metadata".into(),
                ));
            }
            *total = total
                .checked_add(metadata.len())
                .ok_or_else(|| Error::Rejected("source snapshot size overflow".into()))?;
            if *total > MAX_GENERATION_BYTES {
                return Err(Error::Rejected("source snapshot exceeds size limit".into()));
            }
            fs::copy(&source_path, &target_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                fs::set_permissions(
                    &target_path,
                    fs::Permissions::from_mode(metadata.mode() & 0o777),
                )?;
            }
            File::open(&target_path)?.sync_all()?;
        } else {
            return Err(Error::Rejected(
                "source snapshot contains a special file".into(),
            ));
        }
    }
    File::open(target)?.sync_all()?;
    Ok(())
}

fn read_regular_file_stable(path: &Path, expected: &fs::Metadata) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != expected.len() {
        return Err(Error::Rejected(
            "workspace file changed while hashing".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != expected.dev() || opened.ino() != expected.ino() || opened.nlink() != 1 {
            return Err(Error::Rejected(
                "workspace file changed while hashing".into(),
            ));
        }
    }
    let mut content = Vec::with_capacity(expected.len().min(MAX_GENERATION_BYTES) as usize);
    (&mut file)
        .take(MAX_GENERATION_BYTES + 1)
        .read_to_end(&mut content)?;
    let after_read = file.metadata()?;
    let current_path = fs::symlink_metadata(path)?;
    if current_path.file_type().is_symlink()
        || !current_path.is_file()
        || content.len() as u64 != expected.len()
        || content.len() as u64 > MAX_GENERATION_BYTES
        || after_read.len() != expected.len()
    {
        return Err(Error::Rejected(
            "workspace file changed while hashing".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let stable = |left: &fs::Metadata, right: &fs::Metadata| {
            left.dev() == right.dev()
                && left.ino() == right.ino()
                && left.len() == right.len()
                && left.mode() == right.mode()
                && left.mtime() == right.mtime()
                && left.mtime_nsec() == right.mtime_nsec()
                && left.ctime() == right.ctime()
                && left.ctime_nsec() == right.ctime_nsec()
                && left.nlink() == right.nlink()
        };
        if !stable(&opened, &after_read)
            || !stable(&opened, &current_path)
            || current_path.nlink() != 1
        {
            return Err(Error::Rejected(
                "workspace file changed while hashing".into(),
            ));
        }
    }
    Ok(content)
}

fn collect_generation(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<GenerationEntry>,
    total_bytes: &mut u64,
    depth: usize,
) -> Result<()> {
    if depth > 32 {
        return Err(Error::Rejected(
            "workspace generation depth exceeds limit".into(),
        ));
    }
    let mut children: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Rejected(
                "workspace generation contains a symlink".into(),
            ));
        }
        let relative_path = path
            .strip_prefix(root)
            .map_err(|_| Error::Rejected("workspace generation escaped".into()))?;
        let Some(relative_path) = relative_path.to_str() else {
            return Err(Error::Rejected("workspace path is not UTF-8".into()));
        };
        if relative_path.len() > 4096 || relative_path.contains('\\') {
            return Err(Error::Rejected("workspace path is not normalized".into()));
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0;
        if metadata.is_dir() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(Error::Rejected(
                        "workspace directory is not privately owned".into(),
                    ));
                }
            }
            entries.push(GenerationEntry {
                relative_path: relative_path.into(),
                kind: "directory",
                mode,
                byte_len: 0,
                content_digest: None,
            });
            if entries.len() > MAX_GENERATION_FILES * 2 {
                return Err(Error::Rejected(
                    "workspace generation has too many entries".into(),
                ));
            }
            collect_generation(root, &path, entries, total_bytes, depth + 1)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 || metadata.uid() != rustix::process::geteuid().as_raw() {
                    return Err(Error::Rejected(
                        "workspace generation contains a hard link".into(),
                    ));
                }
            }
            if metadata.len() > MAX_GENERATION_BYTES {
                return Err(Error::Rejected("workspace file exceeds size limit".into()));
            }
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| Error::Rejected("workspace generation size overflow".into()))?;
            if *total_bytes > MAX_GENERATION_BYTES || entries.len() >= MAX_GENERATION_FILES * 2 {
                return Err(Error::Rejected(
                    "workspace generation exceeds limits".into(),
                ));
            }
            let content = read_regular_file_stable(&path, &metadata)?;
            entries.push(GenerationEntry {
                relative_path: relative_path.into(),
                kind: "file",
                mode,
                byte_len: content.len() as u64,
                content_digest: Some(digest_bytes(&content)),
            });
        } else {
            return Err(Error::Rejected(
                "workspace generation contains a special file".into(),
            ));
        }
    }
    Ok(())
}

/// Digest the complete workspace generation, including each path, entry type,
/// file mode, byte length, and file content digest.
pub fn workspace_generation_digest(root: &Path) -> Result<String> {
    digest(&workspace_generation_entries(root)?)
}

fn workspace_generation_entries(root: &Path) -> Result<Vec<GenerationEntry>> {
    private_owned(root, true)?;
    let mut entries = Vec::new();
    let mut total_bytes = 0;
    collect_generation(root, root, &mut entries, &mut total_bytes, 0)?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

fn expected_candidate_digest(root: &Path, changes: &[FileChange]) -> Result<String> {
    let mut entries = workspace_generation_entries(root)?;
    for change in changes {
        let (_, mode) = validate_file_change_root(root, change)?;
        let entry = entries
            .binary_search_by(|entry| entry.relative_path.as_str().cmp(&change.relative_path))
            .ok()
            .and_then(|index| entries.get_mut(index))
            .ok_or_else(|| Error::Rejected("patch target is absent from baseline".into()))?;
        if entry.kind != "file" {
            return Err(Error::Rejected(
                "patch target is not a baseline file".into(),
            ));
        }
        entry.mode = mode;
        entry.byte_len = change.after_bytes.len() as u64;
        entry.content_digest = Some(change.after_digest.clone());
    }
    digest(&entries)
}

fn versions_path(root: &Path) -> PathBuf {
    root.join("versions")
}

fn checked_version(root: &Path, name: &str) -> Result<PathBuf> {
    if !valid_generation_name(name) {
        return Err(Error::Rejected(
            "workspace generation name is invalid".into(),
        ));
    }
    let versions = fs::canonicalize(versions_path(root))?;
    let candidate = fs::canonicalize(versions.join(name))?;
    if candidate.parent() != Some(versions.as_path()) {
        return Err(Error::Rejected(
            "workspace generation escaped versions".into(),
        ));
    }
    private_owned(&candidate, true)?;
    Ok(candidate)
}

fn valid_generation_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Resolve the active immutable workspace generation from the atomic pointer.
pub fn active_checkout(workspace_root: &Path) -> Result<PathBuf> {
    let link = workspace_root.join("current");
    let metadata = fs::symlink_metadata(&link)?;
    if !metadata.file_type().is_symlink() {
        return Err(Error::Rejected(
            "active workspace pointer is not a symlink".into(),
        ));
    }
    let target = fs::read_link(link)?;
    let components: Vec<_> = target.components().collect();
    if components.len() != 2
        || !matches!(components[0], Component::Normal(name) if name == "versions")
        || !matches!(components[1], Component::Normal(_))
    {
        return Err(Error::Rejected(
            "active workspace pointer is invalid".into(),
        ));
    }
    let name = components[1]
        .as_os_str()
        .to_str()
        .ok_or_else(|| Error::Rejected("active generation name is not UTF-8".into()))?;
    checked_version(workspace_root, name)
}

fn active_version_name(workspace_root: &Path) -> Result<String> {
    let link = fs::read_link(workspace_root.join("current"))?;
    let mut components = link.components();
    if !matches!(components.next(), Some(Component::Normal(name)) if name == "versions") {
        return Err(Error::Rejected(
            "active workspace pointer is invalid".into(),
        ));
    }
    let name = match components.next() {
        Some(Component::Normal(name)) if components.next().is_none() => name,
        _ => {
            return Err(Error::Rejected(
                "active workspace pointer is invalid".into(),
            ))
        }
    };
    name.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Rejected("active generation name is not UTF-8".into()))
}

fn create_active_link(root: &Path, target: &str) -> Result<()> {
    use std::os::unix::fs::symlink;
    let temporary = root.join(format!(".current-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    symlink(target, &temporary)?;
    fs::rename(&temporary, root.join("current"))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn validate_file_change_root(root: &Path, change: &FileChange) -> Result<(PathBuf, u32)> {
    validate_relative_path(&change.relative_path)?;
    let target = root.join(&change.relative_path);
    let metadata = fs::symlink_metadata(&target)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::Rejected("patch target is not a regular file".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(Error::Rejected(
                "patch target has multiple hard links".into(),
            ));
        }
    }
    let before = read_regular_file_stable(&target, &metadata)?;
    if before != change.before_bytes || digest_bytes(&before) != change.before_digest {
        return Err(Error::Rejected("patch target baseline mismatch".into()));
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o600;
    Ok((target, mode))
}

fn write_candidate_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    transaction_digest: &str,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Rejected("patch target has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Rejected("patch target name is invalid".into()))?;
    let temporary = parent.join(format!(".{name}.{transaction_digest}.stage"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn config_digest(config: &Config) -> Result<String> {
    digest(config)
}

fn state_path(config: &Config) -> PathBuf {
    config.workspace_root.join("control/transaction-state.json")
}

fn validate_durable_state(state: &DurableState) -> Result<()> {
    if state.used_nonces.contains(&0) {
        return Err(Error::Rejected(
            "transaction state has invalid nonce".into(),
        ));
    }
    for (request_digest, receipt) in &state.completed {
        if !valid_digest(request_digest)
            || receipt.request_digest != *request_digest
            || receipt.state_slice != STATE_SLICE
            || !valid_id(&receipt.transaction_id)
            || !valid_digest(&receipt.before_workspace_digest)
            || receipt
                .after_workspace_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || receipt
                .evaluator_receipt_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || receipt.applied_paths != sorted_unique_paths(&receipt.applied_paths)
        {
            return Err(Error::Rejected(
                "transaction state receipt binding is invalid".into(),
            ));
        }
        for path in &receipt.applied_paths {
            validate_relative_path(path)?;
        }
        let consistent = match receipt.status {
            TransactionStatus::Applied => {
                receipt.after_workspace_digest.is_some()
                    && receipt.evaluator_receipt_digest.is_some()
                    && !receipt.rolled_back
                    && !receipt.applied_paths.is_empty()
            }
            TransactionStatus::Rejected => {
                receipt.after_workspace_digest.is_none()
                    && !receipt.rolled_back
                    && receipt.applied_paths.is_empty()
            }
            TransactionStatus::RolledBack => {
                receipt.rolled_back && receipt.applied_paths.is_empty()
            }
            TransactionStatus::Frozen => !receipt.rolled_back && receipt.applied_paths.is_empty(),
        };
        if !consistent {
            return Err(Error::Rejected(
                "transaction state receipt status is inconsistent".into(),
            ));
        }
    }
    if let Some(intent) = &state.in_flight {
        if !valid_id(&intent.transaction_id)
            || !valid_digest(&intent.request_digest)
            || intent.nonce == 0
            || state.used_nonces.contains(&intent.nonce)
            || !valid_digest(&intent.baseline_digest)
            || !valid_generation_name(&intent.old_version)
            || !valid_generation_name(&intent.candidate_version)
            || intent.candidate_version != candidate_name(&intent.request_digest)
            || intent
                .candidate_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || (intent.phase == IntentPhase::Preparing && intent.candidate_digest.is_some())
            || (intent.phase != IntentPhase::Preparing && intent.candidate_digest.is_none())
            || state.completed.contains_key(&intent.request_digest)
        {
            return Err(Error::Rejected(
                "transaction state in-flight binding is invalid".into(),
            ));
        }
    }
    Ok(())
}

fn load_state(config: &Config) -> Result<DurableState> {
    let path = state_path(config);
    let expected_config_digest = config_digest(config)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DurableState {
            version: PROCESS_VERSION,
            config_digest: expected_config_digest,
            frozen: false,
            used_nonces: BTreeSet::new(),
            in_flight: None,
            completed: BTreeMap::new(),
        }),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            if metadata.len() > MAX_STATE_BYTES {
                return Err(Error::Rejected(
                    "transaction state exceeds size limit".into(),
                ));
            }
            private_owned(&path, false)?;
            let bytes = fs::read(&path)?;
            let state: DurableState = serde_json::from_slice(&bytes)?;
            if canonical_bytes(&state)? != bytes
                || state.version != PROCESS_VERSION
                || state.config_digest != expected_config_digest
                || state.completed.len() > MAX_COMPLETED_TRANSACTIONS
            {
                return Err(Error::Rejected(
                    "transaction state binding is invalid".into(),
                ));
            }
            validate_durable_state(&state)?;
            Ok(state)
        }
        Ok(_) => Err(Error::Rejected(
            "transaction state is not a regular file".into(),
        )),
    }
}

fn save_state(config: &Config, state: &DurableState) -> Result<()> {
    let path = state_path(config);
    let pending = path.with_extension("tmp");
    match fs::symlink_metadata(&pending) {
        Ok(_) => {
            private_owned(&pending, false)?;
            fs::remove_file(&pending)?;
            File::open(path.parent().expect("state path has parent"))?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = canonical_bytes(state)?;
    save_atomic_snapshot_locked(&path, &bytes)
}

fn acquire_workspace_lock(config: &Config) -> Result<File> {
    use rustix::fs::{flock, FlockOperation};
    use std::os::unix::fs::OpenOptionsExt;
    let lock_path = state_path(config).with_extension("lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(&lock_path)?;
    private_owned(&lock_path, false)?;
    for _ in 0..500 {
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
    }
    Err(Error::Persistence(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out waiting for managed workspace patch transaction writer lock",
    )))
}

fn candidate_name(transaction_digest: &str) -> String {
    format!("candidate-{}", transaction_digest)
}

fn prepared_from_intent(config: &Config, intent: &Intent) -> Result<PreparedCandidate> {
    let candidate_digest = intent
        .candidate_digest
        .clone()
        .ok_or_else(|| Error::Rejected("candidate preparation is incomplete".into()))?;
    let candidate_root = checked_version(&config.workspace_root, &intent.candidate_version)?;
    if workspace_generation_digest(&candidate_root)? != candidate_digest {
        return Err(Error::Rejected("prepared candidate digest mismatch".into()));
    }
    Ok(PreparedCandidate {
        transaction_digest: intent.request_digest.clone(),
        candidate_digest,
        candidate_root,
    })
}

/// Materialize an exact patch in a new, inactive workspace generation.
pub fn prepare_candidate(config: &Config, request: &PatchRequest) -> Result<PreparedCandidate> {
    validate_config(config)?;
    let now = now_secs()?;
    request.validate(config, now)?;
    let _lock = acquire_workspace_lock(config)?;
    let mut state = load_state(config)?;
    if state.frozen {
        return Err(Error::Rejected("managed workspace is frozen".into()));
    }
    let request_digest = request.digest()?;
    if state.used_nonces.contains(&request.nonce) {
        return Err(Error::Rejected(
            "patch transaction nonce was already used".into(),
        ));
    }
    if let Some(intent) = state.in_flight.as_ref() {
        if intent.request_digest == request_digest && intent.phase == IntentPhase::Prepared {
            return prepared_from_intent(config, intent);
        }
        return Err(Error::Rejected(
            "another patch transaction is in flight".into(),
        ));
    }
    let active_name = active_version_name(&config.workspace_root)?;
    let active = checked_version(&config.workspace_root, &active_name)?;
    if workspace_generation_digest(&active)? != request.checkout_baseline_digest {
        return Err(Error::Rejected(
            "trusted workspace baseline mismatch".into(),
        ));
    }
    for change in &request.changes {
        validate_file_change_root(&active, change)?;
    }
    let candidate_version = candidate_name(&request_digest);
    let candidate = versions_path(&config.workspace_root).join(&candidate_version);
    if candidate.exists() {
        return Err(Error::Rejected(
            "candidate generation already exists".into(),
        ));
    }
    state.in_flight = Some(Intent {
        transaction_id: request.transaction_id.clone(),
        request_digest: request_digest.clone(),
        nonce: request.nonce,
        baseline_digest: request.checkout_baseline_digest.clone(),
        old_version: active_name,
        candidate_version: candidate_version.clone(),
        candidate_digest: None,
        phase: IntentPhase::Preparing,
    });
    save_state(config, &state)?;
    let staged = (|| -> Result<String> {
        fs::create_dir(&candidate)?;
        set_directory_private(&candidate)?;
        File::open(
            candidate
                .parent()
                .ok_or_else(|| Error::Rejected("candidate generation has no parent".into()))?,
        )?
        .sync_all()?;
        copy_tree(&active, &candidate, &mut 0, &mut 0)?;
        for change in &request.changes {
            let (_, mode) = validate_file_change_root(&active, change)?;
            write_candidate_file(
                &candidate.join(&change.relative_path),
                &change.after_bytes,
                mode,
                &request_digest,
            )?;
        }
        if workspace_generation_digest(&active)? != request.checkout_baseline_digest {
            return Err(Error::Rejected(
                "workspace baseline changed while preparing candidate".into(),
            ));
        }
        File::open(
            candidate
                .parent()
                .ok_or_else(|| Error::Rejected("candidate generation has no parent".into()))?,
        )?
        .sync_all()?;
        workspace_generation_digest(&candidate)
    })();
    match staged {
        Ok(candidate_digest) => {
            let intent = state
                .in_flight
                .as_mut()
                .ok_or_else(|| Error::Rejected("patch transaction intent disappeared".into()))?;
            intent.candidate_digest = Some(candidate_digest);
            intent.phase = IntentPhase::Prepared;
            save_state(config, &state)?;
            prepared_from_intent(config, state.in_flight.as_ref().unwrap())
        }
        Err(error) => {
            state.frozen = true;
            if candidate.exists() {
                let _ = fs::remove_dir_all(&candidate);
            }
            state.in_flight = None;
            state.used_nonces.insert(request.nonce);
            let _ = save_state(config, &state);
            Err(error)
        }
    }
}

fn validate_evaluation(
    config: &Config,
    request: &PatchRequest,
    prepared: &PreparedCandidate,
    receipt: &EvaluationReceipt,
    now: u64,
) -> Result<()> {
    let request_digest = request.digest()?;
    if !receipt.accepted
        || receipt.state_slice != STATE_SLICE
        || receipt.transaction_digest != request_digest
        || receipt.patch_digest != request.patch_digest()?
        || receipt.baseline_digest != request.checkout_baseline_digest
        || receipt.candidate_digest != prepared.candidate_digest
        || receipt.nonce != request.nonce
        || receipt.evaluator_executable_digest != config.evaluator_executable_digest
        || receipt.evaluator_input_digest != config.evaluator_input_digest
        || receipt.evaluator_tests_digest != config.evaluator_tests_digest
        || receipt.policy_digest != config.policy_digest
        || receipt.allowed_paths_digest != digest(&config.allowed_paths)?
        || receipt.max_files != config.max_files
        || receipt.max_total_bytes != config.max_total_bytes
        || receipt.evaluator_timeout_ms != config.evaluator_timeout_ms
        || receipt.evaluator_max_address_space_bytes != config.evaluator_max_address_space_bytes
        || receipt.evaluated_at < request.issued_at
        || receipt.evaluated_at > now
        || receipt.expires_at <= now
        || receipt.expires_at > request.lease_expires_at
        || receipt.expires_at.saturating_sub(receipt.evaluated_at) > MAX_EVALUATION_AGE_SECS
    {
        return Err(Error::Rejected("evaluator receipt binding failed".into()));
    }
    receipt.verify(&config.evaluator_public_key)
}

fn receipt_outcome(receipt: &TransactionReceipt) -> Result<TransactionOutcome> {
    Ok(TransactionOutcome {
        status: receipt.status,
        transaction_digest: receipt.request_digest.clone(),
        durable_receipt_digest: digest(receipt)?,
        applied_paths: receipt.applied_paths.clone(),
        rolled_back: receipt.rolled_back,
        reason: receipt.reason.clone(),
    })
}

struct TerminalDetails {
    status: TransactionStatus,
    evaluation_digest: Option<String>,
    after_digest: Option<String>,
    rolled_back: bool,
    reason: Option<String>,
}

fn terminal(
    state: &mut DurableState,
    request_digest: &str,
    request: &PatchRequest,
    details: TerminalDetails,
    now: u64,
) -> Result<TransactionOutcome> {
    if state.completed.len() >= MAX_COMPLETED_TRANSACTIONS {
        return Err(Error::Rejected(
            "transaction receipt history is full".into(),
        ));
    }
    let receipt = TransactionReceipt {
        state_slice: STATE_SLICE.into(),
        status: details.status,
        transaction_id: request.transaction_id.clone(),
        request_digest: request_digest.into(),
        evaluator_receipt_digest: details.evaluation_digest,
        before_workspace_digest: request.checkout_baseline_digest.clone(),
        after_workspace_digest: details.after_digest,
        applied_paths: if details.status == TransactionStatus::Applied {
            request
                .changes
                .iter()
                .map(|change| change.relative_path.clone())
                .collect()
        } else {
            Vec::new()
        },
        completed_at: now,
        rolled_back: details.rolled_back,
        reason: details.reason,
    };
    let key = request_digest.to_owned();
    let outcome = receipt_outcome(&receipt)?;
    state.used_nonces.insert(request.nonce);
    state.completed.insert(key, receipt);
    state.in_flight = None;
    Ok(outcome)
}

/// Atomically publish a previously prepared and signed candidate generation.
pub fn commit_candidate(
    config: &Config,
    request: &PatchRequest,
    receipt: &EvaluationReceipt,
) -> Result<TransactionOutcome> {
    validate_config(config)?;
    let now = now_secs()?;
    request.validate(config, now)?;
    let _lock = acquire_workspace_lock(config)?;
    let mut state = load_state(config)?;
    if state.frozen {
        return Err(Error::Rejected("managed workspace is frozen".into()));
    }
    let request_digest = request.digest()?;
    if state.used_nonces.contains(&request.nonce) || state.completed.contains_key(&request_digest) {
        return Err(Error::Rejected(
            "patch transaction was already completed".into(),
        ));
    }
    let intent = state
        .in_flight
        .clone()
        .ok_or_else(|| Error::Rejected("patch transaction is not prepared".into()))?;
    if intent.request_digest != request_digest
        || intent.transaction_id != request.transaction_id
        || intent.nonce != request.nonce
        || intent.baseline_digest != request.checkout_baseline_digest
        || intent.phase != IntentPhase::Prepared
    {
        return Err(Error::Rejected(
            "prepared transaction binding mismatch".into(),
        ));
    }
    let prepared = prepared_from_intent(config, &intent)?;
    validate_evaluation(config, request, &prepared, receipt, now)?;
    if cancellation_requested(&config.cancellation_file)? {
        return Err(Error::Rejected("patch transaction was cancelled".into()));
    }
    if now >= request.lease_expires_at {
        return Err(Error::Rejected("patch transaction lease expired".into()));
    }
    let active_name = active_version_name(&config.workspace_root)?;
    if active_name != intent.old_version {
        return Err(Error::Rejected(
            "active workspace generation changed".into(),
        ));
    }
    let active = checked_version(&config.workspace_root, &active_name)?;
    if workspace_generation_digest(&active)? != request.checkout_baseline_digest {
        return Err(Error::Rejected(
            "workspace baseline changed before commit".into(),
        ));
    }
    if workspace_generation_digest(&prepared.candidate_root)? != receipt.candidate_digest {
        return Err(Error::Rejected(
            "evaluated candidate changed before commit".into(),
        ));
    }
    state.in_flight.as_mut().unwrap().phase = IntentPhase::CommitStarted;
    save_state(config, &state)?;
    let commit_check_at = now_secs()?;
    if cancellation_requested(&config.cancellation_file)?
        || commit_check_at >= request.lease_expires_at
    {
        state.in_flight.as_mut().unwrap().phase = IntentPhase::Prepared;
        save_state(config, &state)?;
        return Err(Error::Rejected(
            "patch transaction cancelled or expired before publication".into(),
        ));
    }
    create_active_link(
        &config.workspace_root,
        &format!("versions/{}", intent.candidate_version),
    )?;
    if std::env::var("PATCH_TRANSACTION_TEST_FAILPOINT")
        .ok()
        .as_deref()
        == Some("after-pointer-swap")
    {
        std::process::exit(90);
    }
    let active_after = active_checkout(&config.workspace_root)?;
    if active_after != prepared.candidate_root
        || workspace_generation_digest(&active_after)? != receipt.candidate_digest
    {
        let _ = create_active_link(
            &config.workspace_root,
            &format!("versions/{}", intent.old_version),
        );
        state.frozen = true;
        save_state(config, &state)?;
        return Err(Error::Rejected(
            "workspace generation publish check failed".into(),
        ));
    }
    let mut outcome = terminal(
        &mut state,
        &request_digest,
        request,
        TerminalDetails {
            status: TransactionStatus::Applied,
            evaluation_digest: Some(digest(receipt)?),
            after_digest: Some(receipt.candidate_digest.clone()),
            rolled_back: false,
            reason: None,
        },
        now,
    )?;
    if let Err(error) = save_state(config, &state) {
        let restored = create_active_link(
            &config.workspace_root,
            &format!("versions/{}", intent.old_version),
        )
        .is_ok();
        let mut failed_state = load_state(config)?;
        failed_state.frozen = true;
        if restored {
            failed_state.in_flight = None;
            failed_state.used_nonces.insert(request.nonce);
        }
        let _ = save_state(config, &failed_state);
        return Err(Error::Rejected(format!(
            "terminal receipt persistence failed; workspace restored={restored}: {error}"
        )));
    }
    outcome.durable_receipt_digest = digest(
        state
            .completed
            .get(&request_digest)
            .ok_or_else(|| Error::Rejected("durable transaction receipt is missing".into()))?,
    )?;
    Ok(outcome)
}

/// Recover an interrupted prepare or publish; recovery never resumes a patch.
pub fn recover(config: &Config) -> Result<Option<TransactionOutcome>> {
    validate_config_base(config)?;
    let _lock = acquire_workspace_lock(config)?;
    let mut state = load_state(config)?;
    let Some(intent) = state.in_flight.clone() else {
        return Ok(None);
    };
    let now = now_secs()?;
    let active_name = active_version_name(&config.workspace_root)?;
    let mut restored = false;
    if active_name == intent.candidate_version || active_name == intent.old_version {
        if let Ok(old) = checked_version(&config.workspace_root, &intent.old_version) {
            if workspace_generation_digest(&old)
                .is_ok_and(|actual| actual == intent.baseline_digest)
            {
                create_active_link(
                    &config.workspace_root,
                    &format!("versions/{}", intent.old_version),
                )?;
                restored = active_checkout(&config.workspace_root)? == old
                    && workspace_generation_digest(&old)
                        .is_ok_and(|actual| actual == intent.baseline_digest);
            }
        }
    }
    state.frozen = true;
    state.in_flight = None;
    state.used_nonces.insert(intent.nonce);
    let receipt = TransactionReceipt {
        state_slice: STATE_SLICE.into(),
        status: if restored {
            TransactionStatus::RolledBack
        } else {
            TransactionStatus::Frozen
        },
        transaction_id: intent.transaction_id,
        request_digest: intent.request_digest.clone(),
        evaluator_receipt_digest: None,
        before_workspace_digest: intent.baseline_digest,
        after_workspace_digest: None,
        applied_paths: Vec::new(),
        completed_at: now,
        rolled_back: restored,
        reason: Some("interrupted transaction recovered; workspace remains frozen".into()),
    };
    let outcome = receipt_outcome(&receipt)?;
    if state.completed.len() >= MAX_COMPLETED_TRANSACTIONS {
        return Err(Error::Rejected(
            "transaction receipt history is full".into(),
        ));
    }
    state.completed.insert(intent.request_digest, receipt);
    save_state(config, &state)?;
    Ok(Some(outcome))
}

/// Return a persisted terminal receipt by the exact request digest.
pub fn load_receipt(config: &Config, request_digest: &str) -> Result<Option<TransactionReceipt>> {
    validate_config_base(config)?;
    let _lock = acquire_workspace_lock(config)?;
    Ok(load_state(config)?.completed.get(request_digest).cloned())
}
