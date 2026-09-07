#![forbid(unsafe_code)]
//! Rust-native local implementation of the security-alignment control loop.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! This crate is local pure-data and caller-owned persistence evidence. It
//! does not provide OS isolation, provider execution, authenticated identity,
//! model execution, settlement, or a scientific alignment result.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub mod adapters;
pub mod alignment;
pub mod artifacts;
pub mod audit;
pub mod benchmark;
pub mod checker;
pub mod claims;
pub mod contract;
pub mod custody;
pub mod execution_gate;
pub mod faults;
pub mod governance;
pub mod integration;
pub mod market;
pub mod memory;
pub mod property;
pub mod receipts;
pub mod schema;
pub mod specialist;

pub const STATE_SLICE: &str = "security-alignment-os-foundation-v1";
pub const CLAIM_CEILING: &str =
    "local Rust pure-data control and caller-owned persistence evidence only";

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("quarantined: {0}")]
    Quarantined(String),
    #[error("journal error: {0}")]
    Journal(String),
    #[error("persistence error: {0}")]
    Persistence(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(Error::from)
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(digest_bytes(&canonical_bytes(value)?))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Claim {
    pub guarantees: Vec<String>,
    pub assumptions: Vec<String>,
    pub excludes: Vec<String>,
    pub maturity: u8,
    pub trust_roots: Vec<String>,
    pub valid_until: u64,
    pub provenance_digest: String,
}

impl Claim {
    pub fn validate(&self) -> Result<()> {
        if self
            .guarantees
            .iter()
            .chain(&self.assumptions)
            .chain(&self.excludes)
            .chain(&self.trust_roots)
            .any(|item| item.is_empty())
        {
            return Err(Error::Invalid("claim labels must be non-empty".into()));
        }
        if self.maturity > 3 || !valid_digest(&self.provenance_digest) {
            return Err(Error::Invalid(
                "invalid claim maturity or provenance digest".into(),
            ));
        }
        Ok(())
    }
    fn qualifies(&self, now: u64) -> bool {
        self.validate().is_ok()
            && self.valid_until > now
            && self.maturity >= 1
            && self
                .guarantees
                .iter()
                .any(|item| item == "PolicyCompliance")
            && !self.excludes.iter().any(|item| item == "PolicyCompliance")
            && self
                .assumptions
                .iter()
                .all(|item| self.guarantees.contains(item))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Action {
    Read,
    Write,
    Network,
    Secrets,
    Spend,
    Replicate,
    SelfModify,
    Execute,
}

impl Action {
    pub const fn all() -> [Self; 8] {
        [
            Self::Read,
            Self::Write,
            Self::Network,
            Self::Secrets,
            Self::Spend,
            Self::Replicate,
            Self::SelfModify,
            Self::Execute,
        ]
    }
}

impl From<contract::Authority> for Action {
    fn from(authority: contract::Authority) -> Self {
        match authority {
            contract::Authority::Read => Self::Read,
            contract::Authority::Write => Self::Write,
            contract::Authority::Network => Self::Network,
            contract::Authority::Secrets => Self::Secrets,
            contract::Authority::Spend => Self::Spend,
            contract::Authority::Replicate => Self::Replicate,
            contract::Authority::Execute => Self::Execute,
            contract::Authority::SelfModify => Self::SelfModify,
        }
    }
}

impl From<Action> for contract::Authority {
    fn from(action: Action) -> Self {
        match action {
            Action::Read => Self::Read,
            Action::Write => Self::Write,
            Action::Network => Self::Network,
            Action::Secrets => Self::Secrets,
            Action::Spend => Self::Spend,
            Action::Replicate => Self::Replicate,
            Action::Execute => Self::Execute,
            Action::SelfModify => Self::SelfModify,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Proposal {
    pub candidate_id: String,
    pub agent_id: String,
    pub intent: String,
    pub action: Action,
    pub scope: String,
    pub payload: BTreeMap<String, Value>,
    pub resource_cost: BTreeMap<String, u64>,
    pub source_digest: String,
    pub claims: Vec<Claim>,
    pub nonce: u64,
    pub expires_at: u64,
    pub requests_direct_authority: bool,
}

impl Proposal {
    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
    fn validate_shape(&self, now: u64) -> Result<()> {
        if self.candidate_id.is_empty()
            || self.agent_id.is_empty()
            || self.intent.is_empty()
            || self.scope.is_empty()
        {
            return Err(Error::Invalid(
                "proposal identity and intent are required".into(),
            ));
        }
        if !valid_digest(&self.source_digest) || self.expires_at <= now || self.nonce == 0 {
            return Err(Error::Invalid(
                "proposal digest, nonce, or validity is invalid".into(),
            ));
        }
        if self.claims.iter().any(|claim| claim.validate().is_err()) {
            return Err(Error::Invalid("proposal contains malformed claim".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Policy {
    pub allowed_actions: BTreeSet<Action>,
    pub allowed_scopes: BTreeSet<String>,
    pub max_cost: BTreeMap<String, u64>,
    pub token_ttl: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_actions: [Action::Read, Action::Write].into_iter().collect(),
            allowed_scopes: ["public".into(), "sandbox".into()].into_iter().collect(),
            max_cost: [
                ("cpu_ms".into(), 1_000),
                ("bytes".into(), 1_000_000),
                ("spend".into(), 0),
            ]
            .into_iter()
            .collect(),
            token_ttl: 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capability {
    pub token_id: String,
    pub agent_id: String,
    pub action: Action,
    pub scope: String,
    pub intent_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub budget: BTreeMap<String, u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DecisionKind {
    Accepted,
    Rejected,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub candidate_id: String,
    pub kind: DecisionKind,
    pub reason: String,
    pub candidate_digest: String,
    pub policy_digest: String,
    pub capability: Option<Capability>,
    pub decision_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalEntry {
    pub sequence: u64,
    pub previous_digest: String,
    pub candidate_digest: String,
    pub decision_digest: String,
    pub entry_digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayJournal {
    pub entries: Vec<JournalEntry>,
}

impl ReplayJournal {
    fn append(&mut self, candidate_digest: &str, decision_digest: &str) -> Result<()> {
        if !valid_digest(candidate_digest) || !valid_digest(decision_digest) {
            return Err(Error::Journal(
                "journal references must be lowercase digests".into(),
            ));
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.candidate_digest == candidate_digest)
        {
            return Err(Error::Journal("replayed candidate".into()));
        }
        let previous_digest = self
            .entries
            .last()
            .map(|entry| entry.entry_digest.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let sequence = self.entries.len() as u64;
        let material = (
            &sequence,
            &previous_digest,
            &candidate_digest,
            &decision_digest,
        );
        let entry_digest = digest(&material)?;
        self.entries.push(JournalEntry {
            sequence,
            previous_digest,
            candidate_digest: candidate_digest.into(),
            decision_digest: decision_digest.into(),
            entry_digest,
        });
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        let mut previous = "0".repeat(64);
        let mut seen = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.sequence != index as u64
                || entry.previous_digest != previous
                || !valid_digest(&entry.candidate_digest)
                || !valid_digest(&entry.decision_digest)
                || !valid_digest(&entry.entry_digest)
                || !seen.insert(entry.candidate_digest.clone())
            {
                return Err(Error::Journal("invalid journal chain".into()));
            }
            let expected = digest(&(
                &entry.sequence,
                &entry.previous_digest,
                &entry.candidate_digest,
                &entry.decision_digest,
            ))?;
            if expected != entry.entry_digest {
                return Err(Error::Journal("entry digest mismatch".into()));
            }
            previous = entry.entry_digest.clone();
        }
        Ok(())
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = canonical_bytes(self)?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let journal: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&journal)? != bytes {
            return Err(Error::Journal(
                "journal bytes are not canonical JSON".into(),
            ));
        }
        journal.validate()?;
        Ok(journal)
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

struct Issuance {
    candidate_digest: String,
    decision_digest: String,
    policy_digest: String,
    capability: Capability,
    consumed: bool,
}

pub struct Kernel {
    pub policy: Policy,
    pub journal: ReplayJournal,
    issuances: BTreeMap<String, Issuance>,
    lock: Mutex<()>,
}

impl Kernel {
    pub fn new(policy: Policy) -> Result<Self> {
        Ok(Self {
            policy,
            journal: ReplayJournal::default(),
            issuances: BTreeMap::new(),
            lock: Mutex::new(()),
        })
    }
    fn policy_digest(&self) -> Result<String> {
        digest(&self.policy)
    }
    pub fn admit(&mut self, proposal: &Proposal, now: u64) -> Result<Decision> {
        proposal.validate_shape(now)?;
        if proposal.requests_direct_authority {
            return self.record(
                proposal,
                DecisionKind::Rejected,
                "model requested direct authority",
                None,
            );
        }
        if !self.policy.allowed_actions.contains(&proposal.action)
            || !self.policy.allowed_scopes.contains(&proposal.scope)
        {
            return self.record(
                proposal,
                DecisionKind::Rejected,
                "action or scope is not allowlisted",
                None,
            );
        }
        if proposal.resource_cost.iter().any(|(axis, amount)| {
            self.policy
                .max_cost
                .get(axis)
                .map(|limit| amount > limit)
                .unwrap_or(true)
        }) {
            return self.record(
                proposal,
                DecisionKind::Rejected,
                "resource budget exceeded",
                None,
            );
        }
        if !proposal.claims.iter().any(|claim| claim.qualifies(now)) {
            return self.record(
                proposal,
                DecisionKind::Quarantined,
                "required claim is absent, stale, or malformed",
                None,
            );
        }
        let candidate_digest = proposal.digest()?;
        let policy_digest = self.policy_digest()?;
        let claim_expiry = proposal
            .claims
            .iter()
            .filter(|claim| claim.qualifies(now))
            .map(|claim| claim.valid_until)
            .min()
            .unwrap_or(proposal.expires_at);
        let expires_at = proposal
            .expires_at
            .min(now.saturating_add(self.policy.token_ttl))
            .min(claim_expiry);
        if expires_at <= now {
            return self.record(
                proposal,
                DecisionKind::Quarantined,
                "claim expires before capability",
                None,
            );
        }
        let capability = Capability {
            token_id: digest(&(candidate_digest.clone(), now, policy_digest.clone()))?,
            agent_id: proposal.agent_id.clone(),
            action: proposal.action,
            scope: proposal.scope.clone(),
            intent_digest: digest(&(
                &proposal.agent_id,
                &proposal.intent,
                &proposal.action,
                &proposal.scope,
                &proposal.nonce,
            ))?,
            issued_at: now,
            expires_at,
            budget: proposal.resource_cost.clone(),
        };
        self.record(
            proposal,
            DecisionKind::Accepted,
            "policy satisfied",
            Some(capability),
        )
    }
    fn record(
        &mut self,
        proposal: &Proposal,
        kind: DecisionKind,
        reason: &str,
        capability: Option<Capability>,
    ) -> Result<Decision> {
        let candidate_digest = proposal.digest()?;
        let policy_digest = self.policy_digest()?;
        let decision_digest = digest(&(
            proposal.candidate_id.clone(),
            kind,
            reason,
            candidate_digest.clone(),
            policy_digest.clone(),
            capability.clone(),
        ))?;
        self.journal.append(&candidate_digest, &decision_digest)?;
        let decision = Decision {
            candidate_id: proposal.candidate_id.clone(),
            kind,
            reason: reason.into(),
            candidate_digest: candidate_digest.clone(),
            policy_digest: policy_digest.clone(),
            capability: capability.clone(),
            decision_digest: decision_digest.clone(),
        };
        if let Some(capability) = capability {
            self.issuances.insert(
                candidate_digest.clone(),
                Issuance {
                    candidate_digest,
                    decision_digest,
                    policy_digest,
                    capability,
                    consumed: false,
                },
            );
        }
        Ok(decision)
    }
    pub fn consume(&mut self, proposal: &Proposal, decision: &Decision, now: u64) -> Result<bool> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::Rejected("kernel lock poisoned".into()))?;
        let key = proposal.digest()?;
        let current_policy_digest = self.policy_digest()?;
        let issuance = self
            .issuances
            .get_mut(&key)
            .ok_or_else(|| Error::Rejected("unknown issuance".into()))?;
        if issuance.consumed
            || decision.kind != DecisionKind::Accepted
            || decision.candidate_digest != issuance.candidate_digest
            || decision.decision_digest != issuance.decision_digest
            || decision.policy_digest != issuance.policy_digest
            || decision.policy_digest != current_policy_digest
            || decision.capability.as_ref() != Some(&issuance.capability)
            || issuance.capability.expires_at <= now
        {
            return Ok(false);
        }
        issuance.consumed = true;
        Ok(true)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Runtime {
    pub state: BTreeMap<String, Value>,
    pub audit: Vec<BTreeMap<String, String>>,
    checkpoints: Vec<BTreeMap<String, Value>>,
    frozen: bool,
    killed: bool,
}

impl Runtime {
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    pub fn is_killed(&self) -> bool {
        self.killed
    }

    pub fn audit_journal(&self) -> Result<audit::AuditJournal> {
        audit::AuditJournal::from_records(&self.audit)
    }
    pub fn save_audit(&self, path: &Path) -> Result<()> {
        self.audit_journal()?.save(path)
    }

    pub fn execute(
        &mut self,
        kernel: &mut Kernel,
        proposal: &Proposal,
        decision: &Decision,
        now: u64,
    ) -> Result<bool> {
        if self.frozen || self.killed {
            return Err(Error::Rejected("runtime is frozen or killed".into()));
        }
        if decision.kind != DecisionKind::Accepted {
            return Ok(false);
        }
        let capability = decision
            .capability
            .as_ref()
            .ok_or_else(|| Error::Rejected("accepted decision lacks capability".into()))?;
        if capability.expires_at <= now
            || capability.agent_id != proposal.agent_id
            || capability.action != proposal.action
            || capability.scope != proposal.scope
            || capability.budget != proposal.resource_cost
            || capability.intent_digest
                != digest(&(
                    &proposal.agent_id,
                    &proposal.intent,
                    &proposal.action,
                    &proposal.scope,
                    &proposal.nonce,
                ))?
        {
            return Err(Error::Rejected(
                "capability binding or expiry failed".into(),
            ));
        }
        let write = match proposal.action {
            Action::Read => None,
            Action::Write => {
                let key = proposal
                    .payload
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Rejected("write key missing".into()))?;
                if !key.starts_with(&format!("{}:", proposal.scope)) {
                    return Err(Error::Rejected("write target outside scope".into()));
                }
                let value = proposal
                    .payload
                    .get("value")
                    .cloned()
                    .ok_or_else(|| Error::Rejected("write value missing".into()))?;
                Some((key.to_owned(), value))
            }
            _ => {
                return Err(Error::Rejected(
                    "action is not executable by local runtime".into(),
                ))
            }
        };
        let before = self.state.clone();
        let mut after = before.clone();
        if let Some((key, value)) = &write {
            after.insert(key.clone(), value.clone());
        }
        let candidate_digest = proposal.digest()?;
        let state_digest = digest(&after)?;
        if !kernel.consume(proposal, decision, now)? {
            return Err(Error::Rejected(
                "execution decision already consumed".into(),
            ));
        }
        self.checkpoints.push(before);
        self.state = after;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "event".into(),
            if proposal.action == Action::Write {
                "write"
            } else {
                "read"
            }
            .into(),
        );
        metadata.insert("candidate_digest".into(), candidate_digest);
        metadata.insert("state_digest".into(), state_digest);
        self.audit.push(metadata);
        Ok(true)
    }
    pub fn freeze(&mut self, reason: &str) {
        self.frozen = true;
        self.audit.push(
            [
                ("event".into(), "freeze".into()),
                ("reason".into(), reason.into()),
            ]
            .into_iter()
            .collect(),
        );
    }
    pub fn kill(&mut self, reason: &str) {
        self.killed = true;
        self.frozen = true;
        self.audit.push(
            [
                ("event".into(), "kill".into()),
                ("reason".into(), reason.into()),
            ]
            .into_iter()
            .collect(),
        );
    }
    pub fn rollback(&mut self, reason: &str) -> bool {
        if self.killed || self.frozen {
            return false;
        }
        let Some(checkpoint) = self.checkpoints.pop() else {
            return false;
        };
        self.state = checkpoint;
        self.audit.push(
            [
                ("event".into(), "rollback".into()),
                ("reason".into(), reason.into()),
            ]
            .into_iter()
            .collect(),
        );
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Evidence {
    pub id: String,
    pub source_digest: String,
    pub operator_id: String,
    pub validator_id: String,
    pub reviewer_id: String,
    pub valid_until: u64,
    pub accepted: bool,
    pub revoked: bool,
}

impl Evidence {
    fn valid(&self, now: u64, subject: &str) -> bool {
        self.accepted
            && !self.revoked
            && self.valid_until > now
            && self.source_digest == subject
            && !self.operator_id.is_empty()
            && !self.validator_id.is_empty()
            && !self.reviewer_id.is_empty()
            && self.operator_id != self.validator_id
            && self.operator_id != self.reviewer_id
            && self.validator_id != self.reviewer_id
    }
}

#[derive(Clone, Debug, Default)]
pub struct EvidenceRegistry {
    records: BTreeMap<String, Evidence>,
}

impl EvidenceRegistry {
    pub fn insert(&mut self, evidence: Evidence) -> Result<()> {
        if evidence.id.is_empty()
            || !valid_digest(&evidence.source_digest)
            || evidence.operator_id.is_empty()
            || evidence.validator_id.is_empty()
            || evidence.operator_id == evidence.validator_id
            || evidence.valid_until == 0
            || (evidence.accepted
                && (evidence.reviewer_id.is_empty()
                    || evidence.reviewer_id == evidence.operator_id
                    || evidence.reviewer_id == evidence.validator_id))
            || (!evidence.accepted && !evidence.reviewer_id.is_empty())
        {
            return Err(Error::Invalid("invalid evidence identity".into()));
        }
        if self.records.contains_key(&evidence.id) {
            return Err(Error::Rejected("evidence identity already exists".into()));
        }
        self.records.insert(evidence.id.clone(), evidence);
        Ok(())
    }
    pub fn accept(&mut self, id: &str, reviewer: &str) -> Result<()> {
        let evidence = self
            .records
            .get_mut(id)
            .ok_or_else(|| Error::Quarantined("missing evidence".into()))?;
        if reviewer.is_empty()
            || evidence.revoked
            || evidence.accepted
            || reviewer == evidence.operator_id
            || reviewer == evidence.validator_id
        {
            return Err(Error::Rejected("reviewer role collision".into()));
        }
        evidence.reviewer_id = reviewer.into();
        evidence.accepted = true;
        Ok(())
    }
    pub fn is_valid(&self, id: &str, now: u64, subject: &str) -> bool {
        valid_digest(subject) && self.records.get(id).is_some_and(|e| e.valid(now, subject))
    }
    pub fn revoke(&mut self, id: &str) -> Result<()> {
        self.records
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("unknown evidence".into()))
            .map(|e| e.revoked = true)
    }
}

pub fn run_local_workflow(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    evidence: &EvidenceRegistry,
    evidence_id: &str,
    proposal: &Proposal,
    now: u64,
) -> Result<&'static str> {
    let subject = proposal.digest()?;
    if !evidence.is_valid(evidence_id, now, &subject) {
        return Ok("quarantined");
    }
    let decision = kernel.admit(proposal, now)?;
    if decision.kind != DecisionKind::Accepted {
        return Ok("rejected");
    }
    runtime.execute(kernel, proposal, &decision, now)?;
    Ok("completed")
}

pub type SharedKernel = Arc<Mutex<Kernel>>;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn claim() -> Claim {
        Claim {
            guarantees: vec!["PolicyCompliance".into()],
            assumptions: vec![],
            excludes: vec!["alignment".into()],
            maturity: 1,
            trust_roots: vec!["local".into()],
            valid_until: 100,
            provenance_digest: "a".repeat(64),
        }
    }
    fn proposal(id: &str) -> Proposal {
        Proposal {
            candidate_id: id.into(),
            agent_id: "agent".into(),
            intent: "write".into(),
            action: Action::Write,
            scope: "sandbox".into(),
            payload: [
                ("key".into(), Value::String("sandbox:key".into())),
                ("value".into(), Value::Number(1.into())),
            ]
            .into_iter()
            .collect(),
            resource_cost: [
                ("cpu_ms".into(), 1),
                ("bytes".into(), 1),
                ("spend".into(), 0),
            ]
            .into_iter()
            .collect(),
            source_digest: "b".repeat(64),
            claims: vec![claim()],
            nonce: 1,
            expires_at: 50,
            requests_direct_authority: false,
        }
    }

    #[test]
    fn end_to_end_completion_and_replay() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let p = proposal("one");
        let subject = p.digest().unwrap();
        let mut evidence = EvidenceRegistry::default();
        evidence
            .insert(Evidence {
                id: "e".into(),
                source_digest: subject,
                operator_id: "operator".into(),
                validator_id: "validator".into(),
                reviewer_id: "".into(),
                valid_until: 100,
                accepted: false,
                revoked: false,
            })
            .unwrap();
        evidence.accept("e", "reviewer").unwrap();
        assert_eq!(
            run_local_workflow(&mut kernel, &mut runtime, &evidence, "e", &p, 10).unwrap(),
            "completed"
        );
        assert_eq!(
            runtime.state.get("sandbox:key"),
            Some(&Value::Number(1.into()))
        );
        checker::validate_replay(&kernel.journal).unwrap();
        assert!(matches!(
            run_local_workflow(&mut kernel, &mut runtime, &evidence, "e", &p, 10),
            Err(Error::Journal(_))
        ));
    }

    #[test]
    fn rollback_restores_latest_checkpoint_and_preserves_earlier_state() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        for (id, value) in [("one", 1), ("two", 2)] {
            let mut p = proposal(id);
            p.payload
                .insert("value".into(), Value::Number(value.into()));
            let decision = kernel.admit(&p, 10).unwrap();
            assert!(runtime.execute(&mut kernel, &p, &decision, 10).unwrap());
        }
        assert_eq!(
            runtime.state.get("sandbox:key"),
            Some(&Value::Number(2.into()))
        );
        assert!(runtime.rollback("latest failure"));
        assert_eq!(
            runtime.state.get("sandbox:key"),
            Some(&Value::Number(1.into()))
        );
        assert!(runtime.rollback("first failure"));
        assert!(runtime.state.is_empty());
        assert!(!runtime.rollback("nothing left"));
    }

    #[test]
    fn malformed_write_is_rejected_before_capability_consumption() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let mut p = proposal("malformed");
        p.payload.remove("key");
        let decision = kernel.admit(&p, 10).unwrap();
        assert!(runtime.execute(&mut kernel, &p, &decision, 10).is_err());
        assert!(matches!(
            runtime.execute(&mut kernel, &p, &decision, 10),
            Err(Error::Rejected(message)) if message == "write key missing"
        ));
    }

    #[test]
    fn capability_payload_tampering_does_not_consume_original_issuance() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let p = proposal("capability-tamper");
        let decision = kernel.admit(&p, 10).unwrap();
        let mut tampered = decision.clone();
        tampered
            .capability
            .as_mut()
            .expect("accepted decision has capability")
            .token_id = "f".repeat(64);
        assert!(runtime.execute(&mut kernel, &p, &tampered, 10).is_err());
        assert!(runtime.execute(&mut kernel, &p, &decision, 10).unwrap());
    }

    #[test]
    fn evidence_rejects_duplicate_and_colliding_roles() {
        let mut registry = EvidenceRegistry::default();
        let base = Evidence {
            id: "evidence".into(),
            source_digest: "a".repeat(64),
            operator_id: "operator".into(),
            validator_id: "validator".into(),
            reviewer_id: "".into(),
            valid_until: 100,
            accepted: false,
            revoked: false,
        };
        registry.insert(base.clone()).unwrap();
        assert!(registry.insert(base).is_err());
        let colliding = Evidence {
            id: "colliding".into(),
            validator_id: "operator".into(),
            ..Evidence {
                id: "colliding".into(),
                source_digest: "a".repeat(64),
                operator_id: "operator".into(),
                validator_id: "validator".into(),
                reviewer_id: "".into(),
                valid_until: 100,
                accepted: false,
                revoked: false,
            }
        };
        assert!(registry.insert(colliding).is_err());
        assert!(registry.accept("evidence", "").is_err());
        registry.accept("evidence", "reviewer").unwrap();
        assert!(registry.accept("evidence", "reviewer-2").is_err());
    }

    #[test]
    fn default_policy_blocks_high_risk_capability_classes() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        for (index, action) in [
            Action::Network,
            Action::Secrets,
            Action::Spend,
            Action::Replicate,
            Action::SelfModify,
            Action::Execute,
        ]
        .into_iter()
        .enumerate()
        {
            let mut candidate = proposal(&format!("blocked-{index}"));
            candidate.action = action;
            let decision = kernel.admit(&candidate, 10).unwrap();
            assert_eq!(decision.kind, DecisionKind::Rejected);
            assert!(decision.capability.is_none());
        }
    }

    #[test]
    fn rejection_and_evidence_gates_are_fail_closed() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let mut p = proposal("authority");
        p.requests_direct_authority = true;
        let evidence = EvidenceRegistry::default();
        assert_eq!(
            run_local_workflow(&mut kernel, &mut runtime, &evidence, "missing", &p, 10).unwrap(),
            "quarantined"
        );
        assert!(runtime.state.is_empty());
    }

    #[test]
    fn journal_round_trip_and_tamper_detection() {
        let mut journal = ReplayJournal::default();
        journal.append(&"a".repeat(64), &"b".repeat(64)).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.json");
        journal.save(&path).unwrap();
        assert_eq!(ReplayJournal::load(&path).unwrap(), journal);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 2;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        fs::write(&path, bytes).unwrap();
        assert!(ReplayJournal::load(&path).is_err());
        journal.save(&path).unwrap();
        let canonical = fs::read(&path).unwrap();
        let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
        noncanonical.push(b' ');
        noncanonical.extend(canonical);
        fs::write(&path, noncanonical).unwrap();
        assert!(ReplayJournal::load(&path).is_err());
        journal.save(&path).unwrap();
        let temporary = path.with_extension("tmp");
        fs::copy(&path, &temporary).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(ReplayJournal::recover(&path).unwrap(), journal);
    }

    #[test]
    fn kill_closes_rollback() {
        let mut runtime = Runtime::default();
        runtime.kill("operator");
        assert!(!runtime.rollback("late"));
    }

    #[test]
    fn rust_specialist_and_fixed_market_are_fail_closed() {
        let identity = specialist::SpecialistIdentity {
            specialist_id: "s".into(),
            version: "1".into(),
            code_digest: "c".repeat(64),
            policy_digest: "d".repeat(64),
            issued_at: 0,
        };
        let mut registry = specialist::SpecialistRegistry::default();
        registry.register(identity).unwrap();
        let mut resources = BTreeSet::new();
        resources.insert("note".into());
        let grant =
            specialist::ConsentGrant::new("tenant".into(), "s".into(), resources, 0, 100).unwrap();
        let mut retrieval = specialist::TenantRetrieval::default();
        retrieval
            .put(
                "tenant".into(),
                "note".into(),
                Value::String("local".into()),
            )
            .unwrap();
        retrieval.grant(grant.clone()).unwrap();
        assert_eq!(
            retrieval.retrieve(&registry, &grant, "note", 1).unwrap(),
            Value::String("local".into())
        );
        registry.revoke("s").unwrap();
        assert!(retrieval.retrieve(&registry, &grant, "note", 1).is_err());
        let job =
            market::SumJob::new("j".into(), "requester".into(), vec![1, 2, 3], 100, 0).unwrap();
        let receipt = market::execute_local(&job, 10).unwrap();
        let mut verifier = market::ReceiptVerifier::default();
        assert!(verifier.verify(&job, &receipt, 11).unwrap());
        checker::validate_receipt(&job, &receipt, 11).unwrap();
        assert!(
            !verifier.propose_settlement(&job, &receipt, 12).unwrap()["executed"]
                .as_bool()
                .unwrap()
        );
        assert!(verifier.propose_settlement(&job, &receipt, 12).is_err());
        let overflowing = market::SumJob::new(
            "overflow".into(),
            "requester".into(),
            vec![u64::MAX, 1],
            100,
            0,
        );
        assert!(overflowing.is_err());

        let telemetry = specialist::RedactedTelemetry::new(
            specialist::TelemetryEvent::Execution,
            specialist::TelemetryOutcome::Completed,
            "e".repeat(64),
            serde_json::json!({
                "candidate_digest": "a".repeat(64),
                "nested": [{"content": "private", "status": "ok"}],
                "token": "private"
            }),
        )
        .unwrap();
        assert_eq!(
            telemetry.fields["candidate_digest"],
            serde_json::json!("a".repeat(64))
        );
        assert!(telemetry.fields.get("token").is_none());
        assert!(telemetry.fields["nested"][0].get("content").is_none());
    }

    #[test]
    fn rust_audit_round_trip_and_governance_freeze() {
        let mut runtime = Runtime::default();
        runtime.kill("test");
        let journal = runtime.audit_journal().unwrap();
        assert_eq!(journal.entries.len(), 1);
        checker::validate_audit(&journal).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.json");
        runtime.save_audit(&path).unwrap();
        assert_eq!(audit::AuditJournal::load(&path).unwrap(), journal);
        let mut release = governance::ReleaseRegistry::default();
        let candidate = governance::CandidateUpdate {
            candidate_id: "c".into(),
            base_digest: "a".repeat(64),
            candidate_digest: "b".repeat(64),
            rollback_digest: "a".repeat(64),
            evidence_digest: "d".repeat(64),
        };
        release.propose(candidate).unwrap();
        release.advance("c", &"d".repeat(64)).unwrap();
        assert_eq!(release.state("c"), Some(governance::ReleaseState::Canary));
        release.advance("c", &"e".repeat(64)).unwrap();
        assert_eq!(
            release.state("c"),
            Some(governance::ReleaseState::ReleasedLocal)
        );
        release.freeze("c").unwrap();
        assert_eq!(release.state("c"), Some(governance::ReleaseState::Frozen));
    }

    #[test]
    fn rust_benchmark_and_prediction_lock_stay_local() {
        let aggregate = benchmark::run_aggregate("fit").unwrap();
        assert_eq!(aggregate.total, 8);
        assert_eq!(aggregate.passed, aggregate.total);
        let mut lock =
            alignment::PredictionLock::new("protocol", "predictions", "configuration").unwrap();
        assert!(lock.validate().is_err());
        lock.lock_fit();
        assert!(lock.validate().is_err());
        lock.accept_independently();
        assert!(lock.validate().is_ok());
    }

    #[test]
    fn external_adapter_plan_is_typed_but_cannot_authorize_execution() {
        let plan = adapters::AdapterPlan {
            sandbox: adapters::SandboxProfile {
                profile_id: "local-profile".into(),
                executor_digest: "a".repeat(64),
                egress_denied: true,
                secret_broker_required: true,
                independent_kill_path: true,
                memory_bytes: 1,
                cpu_ms: 1,
            },
            invocation: adapters::ToolInvocation {
                invocation_id: "invocation".into(),
                tool_id: "local-tool".into(),
                manifest_digest: "b".repeat(64),
                capability_token_id: "token".into(),
                input_digest: "c".repeat(64),
                consent_grant_id: "grant".into(),
                created_at: 1,
            },
            external_execution_authorized: false,
        };
        assert!(plan.validate().is_ok());
        let mut unauthorized = plan;
        unauthorized.external_execution_authorized = true;
        assert!(unauthorized.validate().is_err());
    }

    #[test]
    fn durable_memory_requires_consent_and_survives_restart() {
        let identity = specialist::SpecialistIdentity {
            specialist_id: "memory-specialist".into(),
            version: "1".into(),
            code_digest: "c".repeat(64),
            policy_digest: "d".repeat(64),
            issued_at: 0,
        };
        let mut registry = specialist::SpecialistRegistry::default();
        registry.register(identity).unwrap();
        let grant = specialist::ConsentGrant::new(
            "tenant".into(),
            "memory-specialist".into(),
            ["note".into()].into_iter().collect(),
            0,
            100,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("memory.json");
        let mut memory = memory::PersistentMemory::open(&path).unwrap();
        let value = serde_json::json!({"kind": "local", "number": 7});
        let value_digest = memory
            .put(&registry, &grant, "note", value.clone(), 1)
            .unwrap();
        assert_eq!(value_digest, digest(&value).unwrap());
        assert_eq!(memory.len(), 1);
        assert_eq!(
            memory.retrieve(&registry, &grant, "note", 1).unwrap(),
            value
        );
        drop(memory);
        let memory = memory::PersistentMemory::open(&path).unwrap();
        assert_eq!(
            memory.retrieve(&registry, &grant, "note", 1).unwrap(),
            value
        );
        assert!(memory.retrieve(&registry, &grant, "missing", 1).is_err());
        assert!(memory.retrieve(&registry, &grant, "note", 100).is_err());
        let forged = specialist::ConsentGrant {
            grant_id: "f".repeat(64),
            ..grant
        };
        assert!(memory.retrieve(&registry, &forged, "note", 1).is_err());
    }

    #[test]
    fn coordinator_rolls_back_and_freezes_on_unhealthy_observation() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let p = proposal("unhealthy");
        let subject = p.digest().unwrap();
        let mut evidence = EvidenceRegistry::default();
        evidence
            .insert(Evidence {
                id: "e".into(),
                source_digest: subject,
                operator_id: "operator".into(),
                validator_id: "validator".into(),
                reviewer_id: "".into(),
                valid_until: 100,
                accepted: false,
                revoked: false,
            })
            .unwrap();
        evidence.accept("e", "reviewer").unwrap();
        let result = integration::run(
            &mut kernel,
            &mut runtime,
            &evidence,
            "e",
            &p,
            integration::Observation {
                at: 10,
                healthy: false,
                telemetry_present: true,
                kill_requested: false,
            },
        )
        .unwrap();
        assert_eq!(result.disposition, integration::Disposition::RolledBack);
        assert!(runtime.state.is_empty());
        assert!(runtime.is_frozen());
        assert!(!runtime.rollback("frozen"));
    }

    #[test]
    fn coordinator_can_require_accepted_artifact_before_execution() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let p = proposal("artifact-bound");
        let subject = p.digest().unwrap();
        let mut evidence = EvidenceRegistry::default();
        evidence
            .insert(Evidence {
                id: "artifact-evidence".into(),
                source_digest: subject,
                operator_id: "operator".into(),
                validator_id: "validator".into(),
                reviewer_id: "".into(),
                valid_until: 100,
                accepted: false,
                revoked: false,
            })
            .unwrap();
        evidence.accept("artifact-evidence", "reviewer").unwrap();
        let mut artifacts = artifacts::ArtifactRegistry::default();
        let manifest = artifacts::ArtifactManifest {
            artifact_id: "source-artifact".into(),
            subject_digest: p.source_digest.clone(),
            source_digest: "c".repeat(64),
            license: "MIT".into(),
            provenance_digest: "d".repeat(64),
            custody_root: "/tmp/local-custody".into(),
            retention_start: 0,
            retention_until: 100,
        };
        artifacts
            .quarantine(manifest, "operator", "validator")
            .unwrap();
        assert!(artifacts
            .accept("source-artifact", &p.source_digest, "reviewer", 10)
            .is_ok());
        let result = integration::run_with_artifact(
            &mut kernel,
            &mut runtime,
            integration::EvidenceBinding {
                evidence: &evidence,
                evidence_id: "artifact-evidence",
                artifacts: &artifacts,
                artifact_id: "source-artifact",
            },
            &p,
            integration::Observation {
                at: 10,
                healthy: true,
                telemetry_present: true,
                kill_requested: false,
            },
        )
        .unwrap();
        assert_eq!(result.disposition, integration::Disposition::Completed);
    }
}
