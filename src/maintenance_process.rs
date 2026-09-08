//! Real, narrowly bounded maintenance process boundary.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module implements one operation only: remove ASCII space characters
//! immediately before a Markdown line ending (and at EOF).  It is deliberately
//! not a patch interpreter or an arbitrary command runner.  The operator owns
//! the checkout, evaluator key, evaluator executable, and durable state.  A
//! hostile process with the same operating-system UID is outside this boundary.

use crate::{canonical_bytes, digest, digest_bytes, valid_digest, Error, Result, STATE_SLICE};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROCESS_VERSION: u8 = 1;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_PATCH_BYTES: usize = 1_048_576;
pub const MAX_EVALUATOR_OUTPUT_BYTES: usize = 32_768;
pub const MAX_JOB_BYTES: usize = MAX_PATCH_BYTES * 9;
pub const EVALUATOR_ROLE: &str = "fixed-maintenance-evaluator-v1";
pub const FIXED_INPUT_IDENTITY: &str = "normalize-trailing-ascii-spaces-v1";
pub const FIXED_POLICY_IDENTITY: &str = "root-level-markdown-single-file-no-arbitrary-code-v1";
pub const FIXED_TEST_IDS: [&str; 6] = [
    "exact-transformation",
    "deterministic-repeat",
    "request-byte-digests",
    "request-live-lease",
    "root-markdown-path",
    "frozen-requirements",
];

pub fn fixed_input_digest() -> String {
    digest_bytes(FIXED_INPUT_IDENTITY.as_bytes())
}

pub fn fixed_tests_digest() -> String {
    digest_bytes(FIXED_TEST_IDS.join("\n").as_bytes())
}

pub fn fixed_policy_digest() -> String {
    digest_bytes(FIXED_POLICY_IDENTITY.as_bytes())
}

/// Operator-owned process configuration. Paths must be absolute and private.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub evaluator_path: PathBuf,
    pub evaluator_seed_path: PathBuf,
    pub evaluator_executable_digest: String,
    /// Lowercase hexadecimal Ed25519 public key.
    pub evaluator_public_key: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub checkout_root: PathBuf,
    pub state_dir: PathBuf,
    pub cancellation_file: PathBuf,
    pub evaluator_timeout_ms: u64,
}

/// Proposer data. The proposer cannot select the evaluator, key, checkout, or
/// seed path; those values are resolved only from [`Config`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Request {
    pub request_id: String,
    pub relative_path: String,
    pub before_bytes: Vec<u8>,
    pub before_digest: String,
    pub after_bytes: Vec<u8>,
    pub after_digest: String,
    /// Digest of every regular file in the trusted checkout at proposal time.
    pub checkout_baseline_digest: String,
    pub lease_expires_at: u64,
    pub nonce: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OutcomeStatus {
    Applied,
    Quarantined,
    RolledBack,
    Frozen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Outcome {
    pub state_slice: String,
    pub status: OutcomeStatus,
    pub reason: Option<String>,
    pub request_digest: String,
    pub before_digest: String,
    pub after_digest: String,
    pub receipt_digest: Option<String>,
    pub rolled_back: bool,
}

/// Signed evaluator result. The signature covers every field except
/// `signature`, in canonical JSON form.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Receipt {
    pub state_slice: String,
    pub request_digest: String,
    pub nonce: u64,
    pub before_digest: String,
    pub after_digest: String,
    pub checkout_baseline_digest: String,
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub evaluated_at: u64,
    pub accepted: bool,
    pub signature: String,
}

impl Receipt {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&ReceiptUnsigned {
            state_slice: &self.state_slice,
            request_digest: &self.request_digest,
            nonce: self.nonce,
            before_digest: &self.before_digest,
            after_digest: &self.after_digest,
            checkout_baseline_digest: &self.checkout_baseline_digest,
            evaluator_executable_digest: &self.evaluator_executable_digest,
            evaluator_input_digest: &self.evaluator_input_digest,
            evaluator_tests_digest: &self.evaluator_tests_digest,
            policy_digest: &self.policy_digest,
            evaluated_at: self.evaluated_at,
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
struct ReceiptUnsigned<'a> {
    state_slice: &'a str,
    request_digest: &'a str,
    nonce: u64,
    before_digest: &'a str,
    after_digest: &'a str,
    checkout_baseline_digest: &'a str,
    evaluator_executable_digest: &'a str,
    evaluator_input_digest: &'a str,
    evaluator_tests_digest: &'a str,
    policy_digest: &'a str,
    evaluated_at: u64,
    accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvaluatorJob {
    pub request: Request,
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub evaluated_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DurableState {
    version: u8,
    config_digest: String,
    frozen: bool,
    consumed_nonces: BTreeSet<u64>,
    in_flight: Option<Intent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Intent {
    request_digest: String,
    relative_path: String,
    before_bytes: Vec<u8>,
    before_digest: String,
    after_digest: String,
    backup_name: String,
}

struct ProcessLock {
    path: PathBuf,
}
impl Drop for ProcessLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Rejected("system clock is before Unix epoch".into()))?
        .as_secs())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
}

fn private_owned(path: &Path, dir: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if (dir && !metadata.is_dir()) || (!dir && !metadata.is_file()) {
        return Err(Error::Rejected(
            "maintenance private path has wrong type".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Rejected(format!(
                "maintenance private path is not owner-only: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        private_owned(path, true)
    } else {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        private_owned(path, true)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Rejected("hex field has wrong length".into()));
    }
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Rejected("hex field is malformed".into()))?;
    }
    Ok(out)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Rejected("atomic path has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| Error::Rejected("atomic path is invalid".into()))?;
    let tmp = parent.join(format!(".{name}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    sync_dir(parent)
}

fn sync_dir(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    file.sync_all()?;
    Ok(())
}

fn load_state(dir: &Path, config_digest: &str) -> Result<DurableState> {
    let path = dir.join("maintenance-state.json");
    if !path.exists() {
        return Ok(DurableState {
            version: PROCESS_VERSION,
            config_digest: config_digest.into(),
            frozen: false,
            consumed_nonces: BTreeSet::new(),
            in_flight: None,
        });
    }
    private_owned(&path, false)?;
    let bytes = fs::read(path)?;
    let state: DurableState = serde_json::from_slice(&bytes)?;
    if state.version != PROCESS_VERSION || state.config_digest != config_digest {
        return Err(Error::Rejected(
            "maintenance state version is unsupported".into(),
        ));
    }
    Ok(state)
}

fn save_state(dir: &Path, state: &DurableState) -> Result<()> {
    atomic_write(
        &dir.join("maintenance-state.json"),
        &canonical_bytes(state)?,
    )
}

fn lock_state(dir: &Path) -> Result<ProcessLock> {
    let path = dir.join("maintenance-state.lock");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| {
            Error::Rejected("maintenance state is busy or requires explicit recovery".into())
        })?;
    file.write_all(std::process::id().to_string().as_bytes())?;
    file.sync_all()?;
    Ok(ProcessLock { path })
}

fn target_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    let mut components = path.components();
    let first = components.next();
    if first.is_none()
        || components.next().is_some()
        || !matches!(first, Some(Component::Normal(_)))
        || relative.contains('\\')
        || relative.contains(':')
        || !relative.ends_with(".md")
    {
        return Err(Error::Rejected(
            "target must be one root-level Markdown file".into(),
        ));
    }
    Ok(root.join(path))
}

fn read_regular_target(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() > MAX_PATCH_BYTES as u64 {
        return Err(Error::Rejected("target exceeds byte limit".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(Error::Rejected("target hardlinks are not allowed".into()));
        }
    }
    if !metadata.is_file() {
        return Err(Error::Rejected("target is not a regular file".into()));
    }
    Ok(fs::read(path)?)
}

fn collect_files(root: &Path, base: &Path, entries: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    if root
        .strip_prefix(base)
        .map_or(usize::MAX, |p| p.components().count())
        > 32
    {
        return Err(Error::Rejected("checkout depth exceeds limit".into()));
    }
    for item in fs::read_dir(root)? {
        let item = item?;
        let path = item.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Rejected("checkout contains a symlink".into()));
        }
        if metadata.is_dir() {
            collect_files(&path, base, entries)?;
        } else if metadata.is_file() {
            if entries.len() >= 4096
                || metadata.len() > 32 * 1024 * 1024
                || entries
                    .iter()
                    .map(|(_, bytes)| bytes.len() as u64)
                    .sum::<u64>()
                    + metadata.len()
                    > 32 * 1024 * 1024
            {
                return Err(Error::Rejected("checkout manifest exceeds limit".into()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(Error::Rejected("checkout contains a hardlink".into()));
                }
            }
            let rel = path
                .strip_prefix(base)
                .map_err(|_| Error::Rejected("checkout path escaped".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push((rel, fs::read(path)?));
        } else {
            return Err(Error::Rejected("checkout contains a special file".into()));
        }
    }
    Ok(())
}

/// Stable digest of the trusted checkout's regular-file bytes and paths.
pub fn checkout_baseline_digest(root: &Path) -> Result<String> {
    private_owned(root, true)?;
    let mut entries = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    digest(&(entries))
}

/// Apply the sole permitted transformation, preserving LF and CRLF endings.
pub fn normalize_trailing_ascii_spaces(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut line_start = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            let has_cr = i > line_start && bytes[i - 1] == b'\r';
            let mut content_end = if has_cr { i - 1 } else { i };
            while content_end > line_start && bytes[content_end - 1] == b' ' {
                content_end -= 1;
            }
            out.extend_from_slice(&bytes[line_start..content_end]);
            if has_cr {
                out.push(b'\r');
            }
            out.push(b'\n');
            line_start = i + 1;
        }
    }
    let mut end = bytes.len();
    while end > line_start && bytes[end - 1] == b' ' {
        end -= 1;
    }
    out.extend_from_slice(&bytes[line_start..end]);
    out
}

fn validate_config(config: &Config) -> Result<()> {
    #[cfg(not(unix))]
    return Err(Error::Rejected("maintenance process requires Unix".into()));
    if !config.evaluator_path.is_absolute()
        || !config.evaluator_seed_path.is_absolute()
        || !config.checkout_root.is_absolute()
        || !config.state_dir.is_absolute()
        || !config.cancellation_file.is_absolute()
        || !valid_digest(&config.evaluator_executable_digest)
        || !valid_digest(&config.evaluator_public_key)
        || config.evaluator_input_digest != fixed_input_digest()
        || config.evaluator_tests_digest != fixed_tests_digest()
        || config.policy_digest != fixed_policy_digest()
        || config.evaluator_timeout_ms == 0
        || config.evaluator_timeout_ms > 60_000
    {
        return Err(Error::Rejected(
            "maintenance configuration is not frozen and bounded".into(),
        ));
    }
    private_owned(&config.checkout_root, true)?;
    private_owned(&config.evaluator_path, false)?;
    private_owned(&config.evaluator_seed_path, false)?;
    if fs::metadata(&config.evaluator_path)?.len() == 0 {
        return Err(Error::Rejected("evaluator executable is empty".into()));
    }
    if digest_bytes(&fs::read(&config.evaluator_path)?) != config.evaluator_executable_digest {
        return Err(Error::Rejected(
            "evaluator executable digest mismatch".into(),
        ));
    }
    decode_fixed::<32>(&config.evaluator_public_key)?;
    ensure_private_dir(&config.state_dir)?;
    let checkout = fs::canonicalize(&config.checkout_root)?;
    let state = fs::canonicalize(&config.state_dir)?;
    if checkout != config.checkout_root
        || state != config.state_dir
        || state.starts_with(&checkout)
        || checkout.starts_with(&state)
        || config.evaluator_path.starts_with(&checkout)
        || config.evaluator_seed_path.starts_with(&checkout)
        || config.cancellation_file.starts_with(&checkout)
    {
        return Err(Error::Rejected(
            "checkout and control paths must be canonical and disjoint".into(),
        ));
    }
    Ok(())
}

pub fn validate_request(request: &Request, now: u64) -> Result<()> {
    if !valid_id(&request.request_id)
        || request.nonce == 0
        || request.lease_expires_at <= now
        || request.before_bytes.len() > MAX_PATCH_BYTES
        || request.after_bytes.len() > MAX_PATCH_BYTES
        || !valid_digest(&request.before_digest)
        || !valid_digest(&request.after_digest)
        || !valid_digest(&request.checkout_baseline_digest)
        || request.before_bytes == request.after_bytes
        || request.before_digest != digest_bytes(&request.before_bytes)
        || request.after_digest != digest_bytes(&request.after_bytes)
    {
        return Err(Error::Rejected(
            "maintenance request bytes or lease are invalid".into(),
        ));
    }
    target_path(Path::new("/"), &request.relative_path)?;
    Ok(())
}

/// Independently evaluate the fixed operation. No caller-supplied test result
/// is accepted: every assertion is recomputed from the request bytes.
pub fn evaluate_job(job: &EvaluatorJob) -> Result<Receipt> {
    let evaluated_at = now_secs()?;
    validate_request(&job.request, evaluated_at)?;
    if job.evaluator_input_digest != fixed_input_digest()
        || job.evaluator_tests_digest != fixed_tests_digest()
        || job.policy_digest != fixed_policy_digest()
        || !valid_digest(&job.evaluator_executable_digest)
    {
        return Err(Error::Rejected(
            "evaluator job is not bound to frozen requirements".into(),
        ));
    }
    let expected = normalize_trailing_ascii_spaces(&job.request.before_bytes);
    if expected != job.request.after_bytes
        || normalize_trailing_ascii_spaces(&job.request.before_bytes) != expected
    {
        return Err(Error::Rejected(
            "candidate does not equal fixed transformation".into(),
        ));
    }
    if job.request.relative_path.contains('/')
        || job.request.relative_path.contains('\\')
        || job.request.relative_path.starts_with('.')
    {
        return Err(Error::Rejected(
            "fixed evaluator path assertion failed".into(),
        ));
    }
    if job.evaluated_at >= job.request.lease_expires_at {
        return Err(Error::Rejected("evaluator lease is expired".into()));
    }
    Ok(Receipt {
        state_slice: STATE_SLICE.into(),
        request_digest: digest(&job.request)?,
        nonce: job.request.nonce,
        before_digest: job.request.before_digest.clone(),
        after_digest: job.request.after_digest.clone(),
        checkout_baseline_digest: job.request.checkout_baseline_digest.clone(),
        evaluator_executable_digest: job.evaluator_executable_digest.clone(),
        evaluator_input_digest: job.evaluator_input_digest.clone(),
        evaluator_tests_digest: job.evaluator_tests_digest.clone(),
        policy_digest: job.policy_digest.clone(),
        evaluated_at,
        accepted: true,
        signature: String::new(),
    })
}

fn cancelled(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}
fn expired(request: &Request) -> bool {
    now_secs()
        .map(|now| now >= request.lease_expires_at)
        .unwrap_or(true)
}

fn base(
    request: &Request,
    status: OutcomeStatus,
    reason: impl Into<Option<String>>,
    rolled_back: bool,
) -> Outcome {
    Outcome {
        state_slice: STATE_SLICE.into(),
        status,
        reason: reason.into(),
        request_digest: digest(request).unwrap_or_default(),
        before_digest: request.before_digest.clone(),
        after_digest: request.after_digest.clone(),
        receipt_digest: None,
        rolled_back,
    }
}

fn recover(config: &Config, state: &mut DurableState) -> Result<bool> {
    let Some(intent) = state.in_flight.clone() else {
        return Ok(false);
    };
    let target = target_path(&config.checkout_root, &intent.relative_path)?;
    let backup = config.state_dir.join(&intent.backup_name);
    if !intent.backup_name.starts_with("maintenance-")
        || Path::new(&intent.backup_name).components().count() != 1
    {
        state.frozen = true;
        save_state(&config.state_dir, state)?;
        return Ok(true);
    }
    private_owned(&backup, false)?;
    let baseline = fs::read(&backup)?;
    if baseline != intent.before_bytes || digest_bytes(&baseline) != intent.before_digest {
        state.frozen = true;
        save_state(&config.state_dir, state)?;
        return Ok(true);
    }
    let current = read_regular_target(&target)?;
    if current != baseline && digest_bytes(&current) != intent.after_digest {
        state.frozen = true;
        save_state(&config.state_dir, state)?;
        return Ok(true);
    }
    if current != baseline {
        restore_atomic(&target, &baseline, &intent.request_digest)?;
    }
    if read_regular_target(&target)? != baseline {
        state.frozen = true;
        save_state(&config.state_dir, state)?;
        return Ok(true);
    }
    state.in_flight = None;
    state.frozen = true;
    save_state(&config.state_dir, state)?;
    let _ = fs::remove_file(backup);
    Ok(true)
}

fn restore_atomic(target: &Path, bytes: &[u8], request_digest: &str) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| Error::Rejected("target has no parent".into()))?;
    let tmp = parent.join(format!(".maintenance-{request_digest}.rollback.tmp"));
    atomic_write(&tmp, bytes)?;
    fs::rename(&tmp, target)?;
    sync_dir(parent)
}

fn invoke_evaluator(
    config: &Config,
    request: &Request,
    executable_digest: &str,
    now: u64,
) -> Result<Receipt> {
    let job = EvaluatorJob {
        request: request.clone(),
        evaluator_executable_digest: executable_digest.into(),
        evaluator_input_digest: config.evaluator_input_digest.clone(),
        evaluator_tests_digest: config.evaluator_tests_digest.clone(),
        policy_digest: config.policy_digest.clone(),
        evaluated_at: now,
    };
    let request_digest = digest(request)?;
    let job_path = config
        .state_dir
        .join(format!("maintenance-{request_digest}.job"));
    atomic_write(&job_path, &canonical_bytes(&job)?)?;
    let _job_cleanup = ProcessLock {
        path: job_path.clone(),
    };
    let job_file = File::open(&job_path)?;
    let mut child = Command::new(&config.evaluator_path)
        .arg("--seed-path")
        .arg(&config.evaluator_seed_path)
        .env_clear()
        .stdin(Stdio::from(job_file))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if cancelled(&config.cancellation_file)
            || expired(request)
            || started.elapsed() >= Duration::from_millis(config.evaluator_timeout_ms)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Rejected(
                "evaluator cancelled or lease expired".into(),
            ));
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let _ = fs::remove_file(&job_path);
    if !status.success() {
        return Err(Error::Rejected("evaluator process failed".into()));
    }
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| Error::Rejected("evaluator stdout unavailable".into()))?
        .take((MAX_EVALUATOR_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > MAX_EVALUATOR_OUTPUT_BYTES {
        return Err(Error::Rejected("evaluator output exceeds bound".into()));
    }
    Ok(serde_json::from_slice(&output)?)
}

/// Execute one fixed maintenance request and return a bounded, typed outcome.
pub fn run(config: &Config, request: &Request) -> Result<Outcome> {
    let now = now_secs()?;
    let request_digest = digest(request)?;
    if let Err(error) = validate_config(config) {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some(error.to_string()),
            false,
        ));
    }
    let _lock = lock_state(&config.state_dir)?;
    let mut state = load_state(&config.state_dir, &digest(config)?)?;
    let recovery = recover(config, &mut state);
    if recovery.is_err() {
        state.frozen = true;
        save_state(&config.state_dir, &state)?;
    }
    if recovery? {
        return Ok(base(
            request,
            OutcomeStatus::Frozen,
            Some("recovered in-flight transaction; process is frozen".into()),
            state.in_flight.is_none(),
        ));
    }
    if state.frozen {
        return Ok(base(
            request,
            OutcomeStatus::Frozen,
            Some("durable maintenance state is frozen".into()),
            false,
        ));
    }
    if let Err(error) = validate_request(request, now) {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some(error.to_string()),
            false,
        ));
    }
    if state.consumed_nonces.contains(&request.nonce) {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some("request nonce was already consumed".into()),
            false,
        ));
    }
    if cancelled(&config.cancellation_file) || expired(request) {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some("request was cancelled or expired".into()),
            false,
        ));
    }
    let target = target_path(&config.checkout_root, &request.relative_path)?;
    let current = read_regular_target(&target)?;
    if current != request.before_bytes
        || digest_bytes(&current) != request.before_digest
        || checkout_baseline_digest(&config.checkout_root)? != request.checkout_baseline_digest
    {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some("trusted checkout baseline mismatch".into()),
            false,
        ));
    }
    let exe_digest = digest_bytes(&fs::read(&config.evaluator_path)?);
    let receipt = match invoke_evaluator(config, request, &exe_digest, now) {
        Ok(value) => value,
        Err(error) => {
            return Ok(base(
                request,
                OutcomeStatus::Quarantined,
                Some(error.to_string()),
                false,
            ))
        }
    };
    if cancelled(&config.cancellation_file)
        || expired(request)
        || !receipt.accepted
        || receipt.state_slice != STATE_SLICE
        || receipt.request_digest != request_digest
        || receipt.nonce != request.nonce
        || receipt.before_digest != request.before_digest
        || receipt.after_digest != request.after_digest
        || receipt.checkout_baseline_digest != request.checkout_baseline_digest
        || receipt.evaluator_executable_digest != config.evaluator_executable_digest
        || receipt.evaluator_input_digest != config.evaluator_input_digest
        || receipt.evaluator_tests_digest != config.evaluator_tests_digest
        || receipt.policy_digest != config.policy_digest
        || receipt.evaluated_at < now
        || receipt.evaluated_at > now_secs()?
        || receipt.evaluated_at >= request.lease_expires_at
        || receipt.verify(&config.evaluator_public_key).is_err()
    {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some("evaluator receipt binding failed".into()),
            false,
        ));
    }
    if cancelled(&config.cancellation_file)
        || expired(request)
        || checkout_baseline_digest(&config.checkout_root)? != request.checkout_baseline_digest
    {
        return Ok(base(
            request,
            OutcomeStatus::Quarantined,
            Some("request was cancelled or expired before write".into()),
            false,
        ));
    }
    let backup_name = format!("maintenance-{request_digest}.backup");
    let backup = config.state_dir.join(&backup_name);
    atomic_write(
        &config
            .state_dir
            .join(format!("maintenance-{request_digest}.receipt.json")),
        &canonical_bytes(&receipt)?,
    )?;
    atomic_write(&backup, &current)?;
    state.consumed_nonces.insert(request.nonce);
    state.in_flight = Some(Intent {
        request_digest: request_digest.clone(),
        relative_path: request.relative_path.clone(),
        before_bytes: current.clone(),
        before_digest: request.before_digest.clone(),
        after_digest: request.after_digest.clone(),
        backup_name: backup_name.clone(),
    });
    save_state(&config.state_dir, &state)?;
    if std::env::var("MAINTENANCE_TEST_FAILPOINT").ok().as_deref() == Some("after-durable-intent") {
        std::process::exit(86);
    }
    if cancelled(&config.cancellation_file) || expired(request) {
        return rollback(
            config,
            &mut state,
            &target,
            &current,
            &backup,
            request,
            "cancelled or expired before replacement",
        );
    }
    let tmp = config
        .checkout_root
        .join(format!(".maintenance-{request_digest}.tmp"));
    atomic_write(&tmp, &request.after_bytes)?;
    fs::rename(&tmp, &target)?;
    sync_dir(&config.checkout_root)?;
    if std::env::var("MAINTENANCE_TEST_FAILPOINT").ok().as_deref() == Some("after-replacement") {
        std::process::exit(87);
    }
    if std::env::var("MAINTENANCE_TEST_FAILPOINT").ok().as_deref()
        == Some("cancel-after-replacement")
    {
        atomic_write(&config.cancellation_file, b"test cancellation")?;
    }
    if cancelled(&config.cancellation_file)
        || expired(request)
        || read_regular_target(&target)? != request.after_bytes
    {
        return rollback(
            config,
            &mut state,
            &target,
            &current,
            &backup,
            request,
            "post-replacement check failed",
        );
    }
    state.in_flight = None;
    save_state(&config.state_dir, &state)?;
    let _ = fs::remove_file(backup);
    Ok(Outcome {
        state_slice: STATE_SLICE.into(),
        status: OutcomeStatus::Applied,
        reason: None,
        request_digest,
        before_digest: request.before_digest.clone(),
        after_digest: request.after_digest.clone(),
        receipt_digest: Some(digest(&receipt)?),
        rolled_back: false,
    })
}

fn rollback(
    config: &Config,
    state: &mut DurableState,
    target: &Path,
    baseline: &[u8],
    backup: &Path,
    request: &Request,
    reason: &str,
) -> Result<Outcome> {
    let restored = restore_atomic(target, baseline, &digest(request)?).is_ok()
        && read_regular_target(target).is_ok_and(|bytes| bytes == baseline);
    if restored {
        state.in_flight = None;
        save_state(&config.state_dir, state)?;
        let _ = fs::remove_file(backup);
        Ok(base(
            request,
            OutcomeStatus::RolledBack,
            Some(reason.into()),
            true,
        ))
    } else {
        state.frozen = true;
        save_state(&config.state_dir, state)?;
        Ok(base(
            request,
            OutcomeStatus::Frozen,
            Some("rollback failed; durable state frozen".into()),
            false,
        ))
    }
}
