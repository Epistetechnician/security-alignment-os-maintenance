//! External capability broker vertical slice.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The broker is a separate process boundary. It is the only component that
//! owns a signing key, admits a typed file transformation, consumes a
//! single-use kernel capability, and commits a staged result. The supervisor
//! is a separately spawned executable and is always invoked through a
//! fail-closed platform sandbox backend.

use crate::receipts::{CapabilityReceipt, ReceiptSigner};
use crate::{
    canonical_bytes, digest, digest_bytes, Action, Claim, DecisionKind, Error, EvidenceRegistry,
    Kernel, Policy, Proposal, Result, STATE_SLICE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: u8 = 1;
pub const JOURNAL_VERSION: u8 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_TEXT_LEN: usize = 256;
pub const MAX_BYTES: u64 = 1_000_000;
pub const MAX_RUNTIME_MS: u64 = 5_000;
pub const WORKSPACE_SCOPE: &str = "broker-workspace";
pub const TRANSFORMER_ID: &str = "uppercase-ascii-file-transform-v1";

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

fn now_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| Error::Invalid("system clock precedes Unix epoch".into()))
}

fn random_launch_token() -> Result<String> {
    let mut seed = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    Ok(digest_bytes(&seed))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_LEN && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_relative_path(value: &str) -> bool {
    valid_text(value)
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn canonical_within(root: &Path, path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(Error::Rejected("path escapes broker workspace".into()))
    }
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if !safe_relative_path(relative) {
        return Err(Error::Rejected("relative path is invalid".into()));
    }
    let path = root.join(relative);
    if path.exists() {
        canonical_within(root, &path)
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| Error::Rejected("path has no parent".into()))?;
        let canonical_parent = canonical_within(root, parent)?;
        Ok(canonical_parent.join(
            path.file_name()
                .ok_or_else(|| Error::Rejected("path has no filename".into()))?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FileTransformOperation {
    UppercaseAscii,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileTransformRequest {
    pub request_id: String,
    pub agent_id: String,
    pub subject: String,
    pub evidence_id: String,
    pub operation: FileTransformOperation,
    pub source_relpath: String,
    pub destination_relpath: String,
    pub input_digest: String,
    pub executable_digest: String,
    pub max_bytes: u64,
    pub max_runtime_ms: u64,
    pub requested_at: u64,
    pub expires_at: u64,
    pub nonce: u64,
    pub telemetry_present: bool,
}

impl FileTransformRequest {
    pub fn validate(&self, now: u64) -> Result<()> {
        if !valid_text(&self.request_id)
            || !valid_text(&self.agent_id)
            || !valid_text(&self.subject)
            || !valid_text(&self.evidence_id)
            || !safe_relative_path(&self.source_relpath)
            || !safe_relative_path(&self.destination_relpath)
            || self.source_relpath == self.destination_relpath
            || !valid_digest(&self.input_digest)
            || !valid_digest(&self.executable_digest)
            || self.max_bytes == 0
            || self.max_bytes > MAX_BYTES
            || self.max_runtime_ms == 0
            || self.max_runtime_ms > MAX_RUNTIME_MS
            || self.requested_at > now
            || self.expires_at <= self.requested_at
            || self.expires_at <= now
            || self.nonce == 0
        {
            return Err(Error::Invalid(
                "file transformation request is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn to_proposal(&self) -> Result<Proposal> {
        let mut payload = BTreeMap::new();
        payload.insert("operation".into(), serde_json::to_value(self.operation)?);
        payload.insert(
            "source_relpath".into(),
            Value::String(self.source_relpath.clone()),
        );
        payload.insert(
            "destination_relpath".into(),
            Value::String(self.destination_relpath.clone()),
        );
        payload.insert(
            "input_digest".into(),
            Value::String(self.input_digest.clone()),
        );
        payload.insert(
            "executable_digest".into(),
            Value::String(self.executable_digest.clone()),
        );
        payload.insert("max_bytes".into(), Value::from(self.max_bytes));
        payload.insert("max_runtime_ms".into(), Value::from(self.max_runtime_ms));
        Ok(Proposal {
            candidate_id: self.request_id.clone(),
            agent_id: self.agent_id.clone(),
            intent: TRANSFORMER_ID.into(),
            action: Action::Write,
            scope: WORKSPACE_SCOPE.into(),
            payload,
            resource_cost: [
                ("bytes".into(), self.max_bytes),
                ("cpu_ms".into(), self.max_runtime_ms),
                ("spend".into(), 0),
            ]
            .into_iter()
            .collect(),
            source_digest: self.executable_digest.clone(),
            claims: vec![Claim {
                guarantees: vec!["PolicyCompliance".into()],
                assumptions: vec![],
                excludes: vec![],
                maturity: 1,
                trust_roots: vec!["broker-local-policy".into()],
                valid_until: self.expires_at,
                provenance_digest: self.input_digest.clone(),
            }],
            nonce: self.nonce,
            expires_at: self.expires_at,
            requests_direct_authority: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BrokerHello {
    pub protocol_version: u8,
    pub state_slice: String,
    pub supervisor_digest: String,
    pub issuer_key_id: String,
    pub issuer_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BrokerRequest {
    Hello,
    Execute(Box<FileTransformRequest>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BrokerResponse {
    Hello(BrokerHello),
    Completed {
        request_digest: String,
        decision_digest: String,
        receipt: CapabilityReceipt,
        output_digest: String,
    },
    Rejected {
        request_digest: Option<String>,
        code: String,
    },
    Quarantined {
        request_digest: Option<String>,
        code: String,
        receipt: Option<CapabilityReceipt>,
    },
    Frozen {
        code: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionStatus {
    Admitted,
    Executing,
    Committed,
    RolledBack,
    Quarantined,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransactionEvent {
    pub sequence: u64,
    pub previous_digest: String,
    pub request_digest: String,
    pub agent_id: String,
    pub nonce: u64,
    pub decision_digest: Option<String>,
    pub capability_token_id: Option<String>,
    pub status: TransactionStatus,
    pub output_digest: Option<String>,
    pub entry_digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BrokerJournal {
    pub version: u8,
    pub frozen: bool,
    pub entries: Vec<TransactionEvent>,
}

impl BrokerJournal {
    pub fn new() -> Self {
        Self {
            version: JOURNAL_VERSION,
            frozen: false,
            entries: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != JOURNAL_VERSION {
            return Err(Error::Journal("unsupported broker journal version".into()));
        }
        let mut previous = "0".repeat(64);
        let mut latest = BTreeMap::<String, TransactionStatus>::new();
        for (index, event) in self.entries.iter().enumerate() {
            if event.sequence != index as u64
                || event.previous_digest != previous
                || !valid_digest(&event.request_digest)
                || !valid_text(&event.agent_id)
                || event.nonce == 0
                || event
                    .decision_digest
                    .as_ref()
                    .is_some_and(|value| !valid_digest(value))
                || event
                    .capability_token_id
                    .as_ref()
                    .is_some_and(|value| !valid_digest(value))
                || event
                    .output_digest
                    .as_ref()
                    .is_some_and(|value| !valid_digest(value))
                || !valid_digest(&event.entry_digest)
            {
                return Err(Error::Journal("broker journal event is malformed".into()));
            }
            let prior = latest.get(&event.request_digest).copied();
            let allowed = matches!(
                (prior, event.status),
                (None, TransactionStatus::Admitted)
                    | (
                        None,
                        TransactionStatus::Rejected | TransactionStatus::Quarantined
                    )
                    | (
                        Some(TransactionStatus::Admitted),
                        TransactionStatus::Executing
                    )
                    | (
                        Some(TransactionStatus::Admitted),
                        TransactionStatus::Quarantined
                    )
                    | (
                        Some(TransactionStatus::Executing),
                        TransactionStatus::Committed
                    )
                    | (
                        Some(TransactionStatus::Executing),
                        TransactionStatus::RolledBack
                    )
                    | (
                        Some(TransactionStatus::Executing),
                        TransactionStatus::Quarantined
                    )
            );
            if !allowed {
                return Err(Error::Journal(
                    "invalid broker transaction transition".into(),
                ));
            }
            let material = (
                event.sequence,
                event.previous_digest.clone(),
                event.request_digest.clone(),
                event.agent_id.clone(),
                event.nonce,
                event.decision_digest.clone(),
                event.capability_token_id.clone(),
                event.status,
                event.output_digest.clone(),
            );
            if digest(&material)? != event.entry_digest {
                return Err(Error::Journal("broker journal digest mismatch".into()));
            }
            previous = event.entry_digest.clone();
            latest.insert(event.request_digest.clone(), event.status);
        }
        Ok(())
    }

    pub fn status(&self, request_digest: &str) -> Option<TransactionStatus> {
        self.entries
            .iter()
            .rev()
            .find(|event| event.request_digest == request_digest)
            .map(|event| event.status)
    }

    pub fn replay_status(&self, agent_id: &str, nonce: u64) -> Option<TransactionStatus> {
        self.entries
            .iter()
            .rev()
            .find(|event| event.agent_id == agent_id && event.nonce == nonce)
            .map(|event| event.status)
    }

    pub fn in_flight(&self) -> Vec<TransactionEvent> {
        self.entries
            .iter()
            .filter(|event| {
                matches!(
                    self.status(&event.request_digest),
                    Some(TransactionStatus::Admitted | TransactionStatus::Executing)
                )
            })
            .filter(|event| self.status(&event.request_digest) == Some(event.status))
            .cloned()
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        request_digest: &str,
        agent_id: &str,
        nonce: u64,
        decision_digest: Option<String>,
        capability_token_id: Option<String>,
        status: TransactionStatus,
        output_digest: Option<String>,
    ) -> Result<()> {
        if !valid_digest(request_digest) || !valid_text(agent_id) || nonce == 0 {
            return Err(Error::Journal("broker event identity is malformed".into()));
        }
        if self.entries.iter().any(|event| {
            event.agent_id == agent_id
                && event.nonce == nonce
                && event.request_digest != request_digest
        }) {
            return Err(Error::Journal("broker agent nonce replay".into()));
        }
        if self.status(request_digest).is_none()
            && matches!(
                status,
                TransactionStatus::Executing
                    | TransactionStatus::Committed
                    | TransactionStatus::RolledBack
            )
        {
            return Err(Error::Journal("broker execution was not admitted".into()));
        }
        let previous_digest = self
            .entries
            .last()
            .map(|event| event.entry_digest.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let sequence = self.entries.len() as u64;
        let material = (
            sequence,
            previous_digest.clone(),
            request_digest.to_owned(),
            agent_id.to_owned(),
            nonce,
            decision_digest.clone(),
            capability_token_id.clone(),
            status,
            output_digest.clone(),
        );
        let event = TransactionEvent {
            sequence,
            previous_digest,
            request_digest: request_digest.into(),
            agent_id: agent_id.into(),
            nonce,
            decision_digest,
            capability_token_id,
            status,
            output_digest,
            entry_digest: digest(&material)?,
        };
        self.entries.push(event);
        self.validate()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let journal: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&journal)? != bytes {
            return Err(Error::Journal(
                "broker journal is not canonical JSON".into(),
            ));
        }
        journal.validate()?;
        Ok(journal)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(self)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(journal) => Ok(journal),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let journal = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(journal)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrokerConfig {
    pub socket_path: PathBuf,
    pub workspace: PathBuf,
    pub journal_path: PathBuf,
    pub supervisor_path: PathBuf,
    pub kill_after_executing: bool,
}

pub struct Broker {
    config: BrokerConfig,
    workspace: PathBuf,
    supervisor_digest: String,
    evidence: EvidenceRegistry,
    signer: ReceiptSigner,
    policy: Policy,
    kernel: Kernel,
    journal: BrokerJournal,
    frozen: bool,
}

pub fn executable_digest(path: &Path) -> Result<String> {
    Ok(digest_bytes(&fs::read(path)?))
}

fn broker_policy() -> Policy {
    Policy {
        allowed_actions: [Action::Write].into_iter().collect(),
        allowed_scopes: [WORKSPACE_SCOPE.into()].into_iter().collect(),
        max_cost: [
            ("cpu_ms".into(), MAX_RUNTIME_MS),
            ("bytes".into(), MAX_BYTES),
            ("spend".into(), 0),
        ]
        .into_iter()
        .collect(),
        token_ttl: MAX_RUNTIME_MS / 1000 + 1,
    }
}

impl Broker {
    pub fn new(
        config: BrokerConfig,
        evidence: EvidenceRegistry,
        signer: ReceiptSigner,
    ) -> Result<Self> {
        if config.workspace.exists() {
            let workspace = fs::canonicalize(&config.workspace)?;
            if !workspace.is_dir() {
                return Err(Error::Rejected(
                    "broker workspace is not a directory".into(),
                ));
            }
            let supervisor_digest = executable_digest(&config.supervisor_path)?;
            let mut journal = match BrokerJournal::recover(&config.journal_path) {
                Ok(value) => value,
                Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    BrokerJournal::new()
                }
                Err(error) => return Err(error),
            };
            let in_flight = journal.in_flight();
            if !in_flight.is_empty() {
                journal.frozen = true;
                for event in in_flight {
                    journal.append(
                        &event.request_digest,
                        &event.agent_id,
                        event.nonce,
                        event.decision_digest,
                        event.capability_token_id,
                        TransactionStatus::Quarantined,
                        None,
                    )?;
                }
                journal.save(&config.journal_path)?;
            }
            let frozen = journal.frozen;
            let policy = broker_policy();
            let kernel = Kernel::new(policy.clone())?;
            Ok(Self {
                config,
                workspace,
                supervisor_digest,
                evidence,
                signer,
                policy,
                kernel,
                journal,
                frozen,
            })
        } else {
            Err(Error::Rejected("broker workspace does not exist".into()))
        }
    }

    pub fn hello(&self) -> BrokerHello {
        BrokerHello {
            protocol_version: PROTOCOL_VERSION,
            state_slice: STATE_SLICE.into(),
            supervisor_digest: self.supervisor_digest.clone(),
            issuer_key_id: self.signer.key_id().into(),
            issuer_public_key: self.signer.verifying_key_bytes().to_vec(),
        }
    }

    fn freeze(&mut self) {
        self.frozen = true;
        self.journal.frozen = true;
        let _ = self.journal.save(&self.config.journal_path);
        let _ = self.kernel.freeze_all();
    }

    pub fn handle(&mut self, request: BrokerRequest) -> BrokerResponse {
        if self.frozen && !matches!(request, BrokerRequest::Hello) {
            return BrokerResponse::Frozen {
                code: "broker_frozen".into(),
            };
        }
        match request {
            BrokerRequest::Hello => BrokerResponse::Hello(self.hello()),
            BrokerRequest::Execute(request) => self.handle_execute(*request),
        }
    }

    fn rejected(request_digest: Option<String>, code: &str) -> BrokerResponse {
        BrokerResponse::Rejected {
            request_digest,
            code: code.into(),
        }
    }

    fn quarantined(
        request_digest: Option<String>,
        code: &str,
        receipt: Option<CapabilityReceipt>,
    ) -> BrokerResponse {
        BrokerResponse::Quarantined {
            request_digest,
            code: code.into(),
            receipt,
        }
    }

    fn handle_execute(&mut self, request: FileTransformRequest) -> BrokerResponse {
        let now = match now_seconds() {
            Ok(value) => value,
            Err(_) => return Self::rejected(None, "clock_unavailable"),
        };
        if request.validate(now).is_err() {
            return Self::rejected(None, "invalid_request");
        }
        let proposal = match request.to_proposal() {
            Ok(value) => value,
            Err(_) => return Self::rejected(None, "proposal_encoding_failed"),
        };
        let request_digest = match proposal.digest() {
            Ok(value) => value,
            Err(_) => return Self::rejected(None, "proposal_digest_failed"),
        };
        if self
            .journal
            .replay_status(&request.agent_id, request.nonce)
            .is_some()
            || self.journal.status(&request_digest).is_some()
        {
            return Self::rejected(Some(request_digest), "replay");
        }
        if request.executable_digest != self.supervisor_digest {
            return Self::rejected(Some(request_digest), "executable_digest_mismatch");
        }
        if !request.telemetry_present {
            self.freeze();
            return Self::quarantined(Some(request_digest), "telemetry_missing", None);
        }
        if !self
            .evidence
            .is_valid(&request.evidence_id, now, &request_digest)
        {
            return Self::quarantined(Some(request_digest), "evidence_unavailable", None);
        }
        let source = match safe_join(&self.workspace, &request.source_relpath) {
            Ok(value) => value,
            Err(_) => return Self::quarantined(Some(request_digest), "source_path_escape", None),
        };
        let destination = match safe_join(&self.workspace, &request.destination_relpath) {
            Ok(value) => value,
            Err(_) => {
                return Self::quarantined(Some(request_digest), "destination_path_escape", None)
            }
        };
        if !source.is_file() || destination.exists() {
            return Self::quarantined(Some(request_digest), "file_scope_invalid", None);
        }
        let source_bytes = match fs::read(&source) {
            Ok(value) if value.len() as u64 <= request.max_bytes => value,
            _ => return Self::quarantined(Some(request_digest), "input_size_invalid", None),
        };
        if digest_bytes(&source_bytes) != request.input_digest {
            return Self::quarantined(Some(request_digest), "input_digest_mismatch", None);
        }
        let decision = match self.kernel.admit(&proposal, now) {
            Ok(value) => value,
            Err(_) => return Self::rejected(Some(request_digest), "admission_failed"),
        };
        if decision.kind != DecisionKind::Accepted {
            return Self::quarantined(Some(request_digest), "admission_not_accepted", None);
        }
        let receipt = match self
            .signer
            .issue(&request.subject, &proposal, &decision, &self.policy)
        {
            Ok(value) => value,
            Err(_) => return Self::rejected(Some(request_digest), "receipt_issue_failed"),
        };
        let capability_token_id = decision
            .capability
            .as_ref()
            .map(|value| value.token_id.clone());
        if self
            .journal
            .append(
                &request_digest,
                &request.agent_id,
                request.nonce,
                Some(decision.decision_digest.clone()),
                capability_token_id.clone(),
                TransactionStatus::Admitted,
                None,
            )
            .and_then(|_| self.journal.save(&self.config.journal_path))
            .is_err()
        {
            self.freeze();
            return Self::quarantined(
                Some(request_digest),
                "journal_admission_failed",
                Some(receipt),
            );
        }
        if !self
            .kernel
            .consume(&proposal, &decision, now)
            .unwrap_or(false)
        {
            self.freeze();
            return Self::quarantined(
                Some(request_digest),
                "capability_consume_failed",
                Some(receipt),
            );
        }
        if self
            .journal
            .append(
                &request_digest,
                &request.agent_id,
                request.nonce,
                Some(decision.decision_digest.clone()),
                capability_token_id.clone(),
                TransactionStatus::Executing,
                None,
            )
            .and_then(|_| self.journal.save(&self.config.journal_path))
            .is_err()
        {
            self.freeze();
            return Self::quarantined(
                Some(request_digest),
                "journal_execution_failed",
                Some(receipt),
            );
        }
        if self.config.kill_after_executing {
            std::process::exit(137);
        }
        let launch_token = match random_launch_token() {
            Ok(value) => value,
            Err(_) => {
                self.freeze();
                return Self::quarantined(
                    Some(request_digest),
                    "launch_token_unavailable",
                    Some(receipt),
                );
            }
        };
        let job = SupervisorJob {
            request: request.clone(),
            workspace: self.workspace.clone(),
            expected_output_digest: digest_bytes(
                &source_bytes
                    .iter()
                    .map(|byte| byte.to_ascii_uppercase())
                    .collect::<Vec<_>>(),
            ),
            launch_token_digest: digest_bytes(launch_token.as_bytes()),
        };
        let job_path = self
            .workspace
            .join(format!(".broker-job-{request_digest}.json"));
        let result = self.run_supervisor(
            &job,
            &launch_token,
            &job_path,
            &source,
            &destination,
            &source_bytes,
        );
        let _ = fs::remove_file(&job_path);
        match result {
            Ok(output_digest) => {
                if self.kernel.complete(&proposal).is_err() {
                    let _ = fs::remove_file(&destination);
                    self.freeze();
                    return Self::quarantined(
                        Some(request_digest),
                        "kernel_completion_failed",
                        Some(receipt),
                    );
                }
                if self
                    .journal
                    .append(
                        &request_digest,
                        &request.agent_id,
                        request.nonce,
                        Some(decision.decision_digest.clone()),
                        capability_token_id,
                        TransactionStatus::Committed,
                        Some(output_digest.clone()),
                    )
                    .and_then(|_| self.journal.save(&self.config.journal_path))
                    .is_err()
                {
                    let _ = fs::remove_file(&destination);
                    let _ = self.kernel.rollback(&proposal);
                    self.freeze();
                    return Self::quarantined(
                        Some(request_digest),
                        "commit_record_failed",
                        Some(receipt),
                    );
                }
                BrokerResponse::Completed {
                    request_digest,
                    decision_digest: decision.decision_digest,
                    receipt,
                    output_digest,
                }
            }
            Err(code) => {
                let _ = fs::remove_file(&destination);
                let _ = self.kernel.rollback(&proposal);
                let _ = self
                    .journal
                    .append(
                        &request_digest,
                        &request.agent_id,
                        request.nonce,
                        Some(decision.decision_digest),
                        capability_token_id,
                        TransactionStatus::RolledBack,
                        None,
                    )
                    .and_then(|_| self.journal.save(&self.config.journal_path));
                self.freeze();
                Self::quarantined(Some(request_digest), &code, Some(receipt))
            }
        }
    }

    fn run_supervisor(
        &self,
        job: &SupervisorJob,
        launch_token: &str,
        job_path: &Path,
        source: &Path,
        destination: &Path,
        source_bytes: &[u8],
    ) -> std::result::Result<String, String> {
        if digest_bytes(source_bytes) != job.request.input_digest || destination.exists() {
            return Err("precondition_changed".into());
        }
        let bytes = canonical_bytes(job).map_err(|_| "job_encode_failed".to_owned())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(job_path)
            .map_err(|_| "job_create_failed".to_owned())?;
        file.write_all(&bytes)
            .map_err(|_| "job_write_failed".to_owned())?;
        file.sync_all().map_err(|_| "job_sync_failed".to_owned())?;
        drop(file);
        let mut child = sandbox_command(
            &self.config.supervisor_path,
            job_path,
            &self.workspace,
            launch_token,
        )?;
        let deadline =
            std::time::Instant::now() + Duration::from_millis(job.request.max_runtime_ms);
        loop {
            match child
                .try_wait()
                .map_err(|_| "supervisor_wait_failed".to_owned())?
            {
                Some(status) => {
                    if !status.success() {
                        let mut stderr = String::new();
                        if let Some(stream) = child.stderr.as_mut() {
                            let _ = stream.read_to_string(&mut stderr);
                        }
                        let detail = stderr
                            .lines()
                            .next()
                            .unwrap_or("sandbox supervisor failed")
                            .chars()
                            .take(96)
                            .collect::<String>();
                        return Err(format!(
                            "supervisor_failed_{}_{}",
                            status.code().unwrap_or(-1),
                            digest_bytes(detail.as_bytes())
                        ));
                    }
                    let outcome = read_supervisor_output(&mut child)?;
                    if outcome.output_digest != job.expected_output_digest {
                        return Err("output_digest_mismatch".into());
                    }
                    let final_source =
                        fs::read(source).map_err(|_| "source_read_failed".to_owned())?;
                    if final_source != source_bytes || !destination.exists() {
                        return Err("source_or_commit_invariant_failed".into());
                    }
                    let final_output =
                        fs::read(destination).map_err(|_| "output_read_failed".to_owned())?;
                    if digest_bytes(&final_output) != job.expected_output_digest {
                        return Err("output_validation_failed".into());
                    }
                    return Ok(outcome.output_digest);
                }
                None if std::time::Instant::now() >= deadline => {
                    terminate_workload(&mut child);
                    return Err("supervisor_timeout".into());
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    #[cfg(unix)]
    pub fn serve(mut self) -> Result<()> {
        if self.config.socket_path.exists() {
            fs::remove_file(&self.config.socket_path)?;
        }
        let listener = UnixListener::bind(&self.config.socket_path)?;
        fs::set_permissions(&self.config.socket_path, fs::Permissions::from_mode(0o600))?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if handle_connection(&mut self, stream).is_err() {
                        self.freeze();
                    }
                }
                Err(_) => self.freeze(),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SupervisorJob {
    pub request: FileTransformRequest,
    pub workspace: PathBuf,
    pub expected_output_digest: String,
    pub launch_token_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SupervisorOutcome {
    pub output_digest: String,
    pub bytes_written: u64,
}

pub fn run_supervisor_job(job_path: &Path) -> Result<SupervisorOutcome> {
    let bytes = fs::read(job_path)?;
    if bytes.len() > MAX_FRAME_BYTES
        || canonical_bytes(&serde_json::from_slice::<SupervisorJob>(&bytes)?)? != bytes
    {
        return Err(Error::Rejected("supervisor job is not canonical".into()));
    }
    let job: SupervisorJob = serde_json::from_slice(&bytes)?;
    let launch_token = std::env::var("BROKER_LAUNCH_TOKEN")
        .map_err(|_| Error::Rejected("supervisor launch token missing".into()))?;
    if digest_bytes(launch_token.as_bytes()) != job.launch_token_digest {
        return Err(Error::Rejected("supervisor launch token invalid".into()));
    }
    let running_executable = std::env::current_exe()?;
    if executable_digest(&running_executable)? != job.request.executable_digest {
        return Err(Error::Rejected(
            "supervisor executable binding failed".into(),
        ));
    }
    let workspace = fs::canonicalize(&job.workspace)?;
    let source = safe_join(&workspace, &job.request.source_relpath)?;
    let destination = safe_join(&workspace, &job.request.destination_relpath)?;
    if !source.is_file() || destination.exists() || job.request.executable_digest.is_empty() {
        return Err(Error::Rejected("supervisor file scope is invalid".into()));
    }
    let input = fs::read(&source)?;
    if input.len() as u64 > job.request.max_bytes
        || digest_bytes(&input) != job.request.input_digest
    {
        return Err(Error::Rejected("supervisor input binding failed".into()));
    }
    let output: Vec<u8> = input.iter().map(|byte| byte.to_ascii_uppercase()).collect();
    let output_digest = digest_bytes(&output);
    if output_digest != job.expected_output_digest {
        return Err(Error::Rejected(
            "supervisor output expectation failed".into(),
        ));
    }
    let stage = workspace.join(format!(".broker-stage-{}.tmp", job.expected_output_digest));
    let result = (|| {
        let mut staged = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)?;
        staged.write_all(&output)?;
        staged.sync_all()?;
        if digest_bytes(&fs::read(&source)?) != job.request.input_digest || destination.exists() {
            return Err(std::io::Error::other("source changed during staging"));
        }
        fs::rename(&stage, &destination)?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
        return Err(Error::Rejected("supervisor commit failed".into()));
    }
    Ok(SupervisorOutcome {
        output_digest,
        bytes_written: output.len() as u64,
    })
}

#[cfg(target_os = "macos")]
fn sandbox_command(
    supervisor: &Path,
    job: &Path,
    workspace: &Path,
    launch_token: &str,
) -> std::result::Result<Child, String> {
    let escaped = workspace.to_string_lossy().replace('"', "\\\"");
    let contents = format!(
        "(version 1) (allow default) (deny network*) (deny file-write*) (allow file-read* (subpath \"{escaped}\")) (allow file-write* (subpath \"{escaped}\")) (deny process-exec*) (allow process-exec* (literal \"{}\")) (allow process-fork)",
        supervisor.to_string_lossy().replace('"', "\\\"")
    );
    let child = Command::new("/usr/bin/sandbox-exec")
        .args([
            "-p",
            &contents,
            supervisor
                .to_str()
                .ok_or_else(|| "supervisor_path_failed".to_owned())?,
        ])
        .arg("--job")
        .arg(job)
        .env_clear()
        .env("BROKER_LAUNCH_TOKEN", launch_token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "supervisor_spawn_failed".to_owned());
    child
}

#[cfg(target_os = "linux")]
fn sandbox_command(
    supervisor: &Path,
    job: &Path,
    _workspace: &Path,
    launch_token: &str,
) -> std::result::Result<Child, String> {
    Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--net",
            "--pid",
            "--fork",
            "--mount-proc",
        ])
        .arg(supervisor)
        .arg("--job")
        .arg(job)
        .env_clear()
        .env("BROKER_LAUNCH_TOKEN", launch_token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "linux_unshare_unavailable".to_owned())
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn sandbox_command(
    _supervisor: &Path,
    _job: &Path,
    _workspace: &Path,
    _launch_token: &str,
) -> std::result::Result<Child, String> {
    Err("unsupported_sandbox_platform".into())
}

#[cfg(not(unix))]
fn sandbox_command(
    _supervisor: &Path,
    _job: &Path,
    _workspace: &Path,
    _launch_token: &str,
) -> std::result::Result<Child, String> {
    Err("unsupported_sandbox_platform".into())
}

fn terminate_workload(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_supervisor_output(child: &mut Child) -> std::result::Result<SupervisorOutcome, String> {
    let mut output = String::new();
    if let Some(stdout) = child.stdout.as_mut() {
        stdout
            .read_to_string(&mut output)
            .map_err(|_| "supervisor_output_read_failed".to_owned())?;
    }
    if output.len() > 16 * 1024 {
        return Err("supervisor_output_too_large".into());
    }
    let outcome: SupervisorOutcome =
        serde_json::from_str(&output).map_err(|_| "supervisor_output_invalid".to_owned())?;
    if !valid_digest(&outcome.output_digest) {
        return Err("supervisor_output_digest_invalid".into());
    }
    Ok(outcome)
}

#[cfg(unix)]
fn handle_connection(broker: &mut Broker, stream: UnixStream) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.len() > MAX_FRAME_BYTES {
        return Err(Error::Rejected("IPC frame too large".into()));
    }
    let request: BrokerRequest = serde_json::from_str(line.trim_end())?;
    let response = broker.handle(request);
    let mut writer = stream;
    let encoded = canonical_bytes(&response)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(Error::Rejected("IPC response too large".into()));
    }
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(unix)]
pub struct BrokerClient {
    socket_path: PathBuf,
}

#[cfg(unix)]
impl BrokerClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn request(&self, request: BrokerRequest) -> Result<BrokerResponse> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        let encoded = canonical_bytes(&request)?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(Error::Rejected("IPC request too large".into()));
        }
        stream.write_all(&encoded)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response)?;
        if response.len() > MAX_FRAME_BYTES {
            return Err(Error::Rejected("IPC response too large".into()));
        }
        Ok(serde_json::from_str(response.trim_end())?)
    }

    pub fn hello(&self) -> Result<BrokerHello> {
        match self.request(BrokerRequest::Hello)? {
            BrokerResponse::Hello(value) => Ok(value),
            _ => Err(Error::Rejected("broker hello failed".into())),
        }
    }
}
