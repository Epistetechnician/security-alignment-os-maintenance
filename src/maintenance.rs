//! Bounded, reversible local maintenance workflow.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module is a pure-data contract and an in-memory executor seam. It does
//! not open files, start processes, contact a network, authenticate roles, or
//! provide generic broker patch support. A future caller may implement the
//! executor trait, but this module only supplies the test executor below.

use crate::{digest, digest_bytes, valid_digest, Error, Result, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const MAX_PATH_BYTES: usize = 256;
pub const MAX_PATCH_BYTES: usize = 1_048_576;
pub const MAX_TESTS: usize = 64;

/// These tests are part of the frozen maintenance evaluator contract.
pub const REQUIRED_ADVERSARIAL_TESTS: [&str; 4] = [
    "evidence-substitution",
    "evidence-expiry",
    "path-escape",
    "failed-postcheck-rollback",
];

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_PATH_BYTES && !value.chars().any(char::is_control)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_PATH_BYTES && !value.chars().any(char::is_control)
}

fn safe_relative_path(value: &str) -> bool {
    valid_text(value)
        && !value.contains('\\')
        && !value.contains(':')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_digest_fields(values: &[&str]) -> Result<()> {
    if values.iter().any(|value| !valid_digest(value)) {
        return Err(Error::Invalid("maintenance digest is malformed".into()));
    }
    Ok(())
}

/// Exact evaluator inputs frozen into a maintenance proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceRequirements {
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub required_test_ids: Vec<String>,
}

impl MaintenanceRequirements {
    pub fn validate(&self) -> Result<()> {
        validate_digest_fields(&[
            &self.evaluator_executable_digest,
            &self.evaluator_input_digest,
            &self.evaluator_tests_digest,
            &self.policy_digest,
        ])?;
        if self.required_test_ids.is_empty() || self.required_test_ids.len() > MAX_TESTS {
            return Err(Error::Invalid(
                "maintenance evaluator test requirements are empty or too large".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for id in &self.required_test_ids {
            if !valid_id(id) || !ids.insert(id.clone()) {
                return Err(Error::Invalid(
                    "maintenance evaluator test requirement is malformed or duplicated".into(),
                ));
            }
        }
        if REQUIRED_ADVERSARIAL_TESTS
            .iter()
            .any(|required| !ids.contains(*required))
        {
            return Err(Error::Invalid(
                "required adversarial maintenance tests are missing".into(),
            ));
        }
        Ok(())
    }
}

/// One result from the exact evaluator test roster.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceTestResult {
    pub test_id: String,
    pub passed: bool,
}

impl MaintenanceTestResult {
    fn validate(&self) -> Result<()> {
        if !valid_id(&self.test_id) {
            return Err(Error::Invalid(
                "maintenance test result ID is invalid".into(),
            ));
        }
        Ok(())
    }
}

/// A single-file patch proposal with exact bytes and byte digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenancePatchProposal {
    pub patch_id: String,
    pub proposer_role: String,
    pub relative_path: String,
    pub before_bytes: Vec<u8>,
    pub before_digest: String,
    pub after_bytes: Vec<u8>,
    pub after_digest: String,
    pub requirements: MaintenanceRequirements,
    pub proposed_at: u64,
    pub expires_at: u64,
}

impl MaintenancePatchProposal {
    pub fn validate(&self, now: u64) -> Result<()> {
        if !valid_id(&self.patch_id)
            || !valid_id(&self.proposer_role)
            || !safe_relative_path(&self.relative_path)
            || self.before_bytes.len() > MAX_PATCH_BYTES
            || self.after_bytes.len() > MAX_PATCH_BYTES
            || self.before_bytes == self.after_bytes
            || self.proposed_at > now
            || self.expires_at <= self.proposed_at
            || self.expires_at <= now
        {
            return Err(Error::Invalid(
                "maintenance patch proposal is invalid".into(),
            ));
        }
        validate_digest_fields(&[&self.before_digest, &self.after_digest])?;
        if self.before_digest != digest_bytes(&self.before_bytes)
            || self.after_digest != digest_bytes(&self.after_bytes)
        {
            return Err(Error::Invalid(
                "maintenance patch byte digest does not match bytes".into(),
            ));
        }
        self.requirements.validate()
    }

    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
}

/// Evaluator output. Role fields are assertions supplied by the caller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceEvaluation {
    pub evaluation_id: String,
    pub evaluator_role: String,
    pub proposal_digest: String,
    pub requirements: MaintenanceRequirements,
    pub test_results: Vec<MaintenanceTestResult>,
    pub accepted: bool,
    pub evaluated_at: u64,
    pub expires_at: u64,
}

impl MaintenanceEvaluation {
    pub fn validate_for(&self, proposal: &MaintenancePatchProposal, now: u64) -> Result<()> {
        if !valid_id(&self.evaluation_id)
            || !valid_id(&self.evaluator_role)
            || !valid_digest(&self.proposal_digest)
            || self.evaluator_role == proposal.proposer_role
            || self.evaluated_at > now
            || self.evaluated_at < proposal.proposed_at
            || self.expires_at <= self.evaluated_at
            || self.expires_at <= now
            || self.requirements != proposal.requirements
            || self.proposal_digest != proposal.digest()?
            || self.test_results.is_empty()
            || self.test_results.len() > MAX_TESTS
            || !self.accepted
        {
            return Err(Error::Invalid(
                "maintenance evaluation is stale, mismatched, incomplete, or rejected".into(),
            ));
        }
        let required: BTreeSet<_> = proposal
            .requirements
            .required_test_ids
            .iter()
            .cloned()
            .collect();
        let mut observed = BTreeSet::new();
        for result in &self.test_results {
            result.validate()?;
            if !required.contains(&result.test_id) || !observed.insert(result.test_id.clone()) {
                return Err(Error::Invalid(
                    "maintenance evaluator test result roster does not match requirements".into(),
                ));
            }
            if !result.passed {
                return Err(Error::Invalid(
                    "required maintenance evaluator test failed".into(),
                ));
            }
        }
        if observed != required {
            return Err(Error::Invalid(
                "maintenance evaluator omitted a required test result".into(),
            ));
        }
        Ok(())
    }
}

/// Independent acceptance bound to the exact complete proposal/evaluation packet.
/// The reviewer role is a caller assertion and is not authenticated here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceAcceptance {
    pub reviewer_role: String,
    pub complete_packet_digest: String,
    pub accepted_at: u64,
    pub expires_at: u64,
}

impl MaintenanceAcceptance {
    pub fn validate_for(&self, packet: &MaintenancePacket, now: u64) -> Result<()> {
        if !valid_id(&self.reviewer_role)
            || !valid_digest(&self.complete_packet_digest)
            || self.accepted_at > now
            || self.expires_at <= self.accepted_at
            || self.accepted_at < packet.evaluation.evaluated_at
            || self.expires_at <= now
            || self.complete_packet_digest != packet.digest()?
            || self.reviewer_role == packet.proposal.proposer_role
            || self.reviewer_role == packet.evaluation.evaluator_role
        {
            return Err(Error::Invalid(
                "maintenance acceptance is stale, mismatched, or role-colliding".into(),
            ));
        }
        Ok(())
    }
}

/// The complete packet independently evaluated before a local change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenancePacket {
    pub proposal: MaintenancePatchProposal,
    pub evaluation: MaintenanceEvaluation,
}

impl MaintenancePacket {
    pub fn validate(&self, now: u64) -> Result<()> {
        self.proposal.validate(now)?;
        self.evaluation.validate_for(&self.proposal, now)
    }

    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MaintenanceStatus {
    Applied,
    Quarantined,
    RolledBack,
    Frozen,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MaintenanceReason {
    MissingAcceptance,
    InvalidEvidence,
    ExpiredEvidence,
    MismatchedEvidence,
    ReplayedAcceptance,
    MissingTarget,
    BeforeDigestMismatch,
    WriteFailed,
    PostcheckFailed,
    RollbackFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceOutcome {
    pub state_slice: &'static str,
    pub status: MaintenanceStatus,
    pub reason: Option<MaintenanceReason>,
    pub packet_digest: String,
    pub before_digest: String,
    pub after_digest: String,
}

/// A caller-owned reversible executor seam. Implementations must keep all
/// I/O within their declared local scope; this module provides no real-I/O
/// implementation.
pub trait MaintenanceExecutor {
    fn read(&mut self, relative_path: &str) -> Result<Vec<u8>>;
    fn write(&mut self, relative_path: &str, bytes: &[u8]) -> Result<()>;
}

/// In-memory executor used by hermetic contract tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryMaintenanceExecutor {
    files: BTreeMap<String, Vec<u8>>,
    pub fail_writes: bool,
    pub corrupt_next_write: bool,
    pub fail_rollback_writes: bool,
    writes: usize,
}

impl InMemoryMaintenanceExecutor {
    pub fn with_file(relative_path: impl Into<String>, bytes: Vec<u8>) -> Self {
        let mut executor = Self::default();
        executor.files.insert(relative_path.into(), bytes);
        executor
    }

    pub fn file(&self, relative_path: &str) -> Option<&[u8]> {
        self.files.get(relative_path).map(Vec::as_slice)
    }
}

impl MaintenanceExecutor for InMemoryMaintenanceExecutor {
    fn read(&mut self, relative_path: &str) -> Result<Vec<u8>> {
        self.files
            .get(relative_path)
            .cloned()
            .ok_or_else(|| Error::Rejected("maintenance target is missing".into()))
    }

    fn write(&mut self, relative_path: &str, bytes: &[u8]) -> Result<()> {
        if self.fail_writes {
            return Err(Error::Rejected("maintenance write failed".into()));
        }
        if self.fail_rollback_writes && self.writes > 0 {
            return Err(Error::Rejected("maintenance rollback write failed".into()));
        }
        let mut value = bytes.to_vec();
        if self.corrupt_next_write {
            self.corrupt_next_write = false;
            if let Some(first) = value.first_mut() {
                *first ^= 1;
            } else {
                value.push(1);
            }
        }
        self.files.insert(relative_path.into(), value);
        self.writes += 1;
        Ok(())
    }
}

/// Coordinator state preventing one acceptance from authorizing two changes.
#[derive(Clone, Debug)]
pub struct MaintenanceCoordinator {
    requirements: MaintenanceRequirements,
    evaluator_role: String,
    reviewer_role: String,
    consumed_acceptances: BTreeSet<String>,
    frozen: bool,
}

impl MaintenanceCoordinator {
    pub fn new(
        requirements: MaintenanceRequirements,
        evaluator_role: impl Into<String>,
        reviewer_role: impl Into<String>,
    ) -> Result<Self> {
        requirements.validate()?;
        let evaluator_role = evaluator_role.into();
        let reviewer_role = reviewer_role.into();
        if !valid_id(&evaluator_role)
            || !valid_id(&reviewer_role)
            || evaluator_role == reviewer_role
        {
            return Err(Error::Invalid(
                "maintenance coordinator roles are invalid or collide".into(),
            ));
        }
        Ok(Self {
            requirements,
            evaluator_role,
            reviewer_role,
            consumed_acceptances: BTreeSet::new(),
            frozen: false,
        })
    }

    /// Validate every binding before consuming acceptance and mutating the
    /// caller-owned executor under state slice
    /// `security-alignment-os-foundation-v1`.
    pub fn apply<E: MaintenanceExecutor>(
        &mut self,
        packet: &MaintenancePacket,
        acceptance: Option<&MaintenanceAcceptance>,
        executor: &mut E,
        now: u64,
    ) -> Result<MaintenanceOutcome> {
        let packet_digest = packet.digest()?;
        let base = |status, reason| MaintenanceOutcome {
            state_slice: STATE_SLICE,
            status,
            reason,
            packet_digest: packet_digest.clone(),
            before_digest: packet.proposal.before_digest.clone(),
            after_digest: packet.proposal.after_digest.clone(),
        };

        if self.frozen {
            return Ok(base(
                MaintenanceStatus::Frozen,
                Some(MaintenanceReason::RollbackFailed),
            ));
        }
        if packet.proposal.expires_at <= now || packet.evaluation.expires_at <= now {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::ExpiredEvidence),
            ));
        }
        if packet.proposal.requirements != self.requirements
            || packet.evaluation.requirements != self.requirements
            || packet.evaluation.evaluator_role != self.evaluator_role
            || acceptance.is_some_and(|value| value.reviewer_role != self.reviewer_role)
        {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::MismatchedEvidence),
            ));
        }
        if packet.validate(now).is_err() {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::InvalidEvidence),
            ));
        }
        let Some(acceptance) = acceptance else {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::MissingAcceptance),
            ));
        };
        if self
            .consumed_acceptances
            .contains(&acceptance.complete_packet_digest)
        {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::ReplayedAcceptance),
            ));
        }
        if acceptance.expires_at <= now {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::ExpiredEvidence),
            ));
        }
        if acceptance.validate_for(packet, now).is_err() {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::MismatchedEvidence),
            ));
        }

        let current = match executor.read(&packet.proposal.relative_path) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(base(
                    MaintenanceStatus::Quarantined,
                    Some(MaintenanceReason::MissingTarget),
                ))
            }
        };
        if current != packet.proposal.before_bytes
            || digest_bytes(&current) != packet.proposal.before_digest
        {
            return Ok(base(
                MaintenanceStatus::Quarantined,
                Some(MaintenanceReason::BeforeDigestMismatch),
            ));
        }

        // Consume before the first write so a failed or rolled-back attempt
        // cannot be replayed with the same independent acceptance.
        self.consumed_acceptances
            .insert(acceptance.complete_packet_digest.clone());
        if executor
            .write(&packet.proposal.relative_path, &packet.proposal.after_bytes)
            .is_err()
        {
            let rollback_ok = executor
                .write(
                    &packet.proposal.relative_path,
                    &packet.proposal.before_bytes,
                )
                .is_ok()
                && executor
                    .read(&packet.proposal.relative_path)
                    .is_ok_and(|bytes| bytes == packet.proposal.before_bytes);
            if !rollback_ok {
                self.frozen = true;
            }
            return Ok(if rollback_ok {
                base(
                    MaintenanceStatus::RolledBack,
                    Some(MaintenanceReason::WriteFailed),
                )
            } else {
                base(
                    MaintenanceStatus::Frozen,
                    Some(MaintenanceReason::RollbackFailed),
                )
            });
        }
        let postcheck = executor
            .read(&packet.proposal.relative_path)
            .is_ok_and(|bytes| bytes == packet.proposal.after_bytes);
        if postcheck {
            return Ok(base(MaintenanceStatus::Applied, None));
        }

        let rollback_ok = executor
            .write(
                &packet.proposal.relative_path,
                &packet.proposal.before_bytes,
            )
            .is_ok()
            && executor
                .read(&packet.proposal.relative_path)
                .is_ok_and(|bytes| bytes == packet.proposal.before_bytes);
        if rollback_ok {
            Ok(base(
                MaintenanceStatus::RolledBack,
                Some(MaintenanceReason::PostcheckFailed),
            ))
        } else {
            self.frozen = true;
            Ok(base(
                MaintenanceStatus::Frozen,
                Some(MaintenanceReason::RollbackFailed),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> MaintenanceRequirements {
        MaintenanceRequirements {
            evaluator_executable_digest: "a".repeat(64),
            evaluator_input_digest: "b".repeat(64),
            evaluator_tests_digest: "c".repeat(64),
            policy_digest: "d".repeat(64),
            required_test_ids: REQUIRED_ADVERSARIAL_TESTS
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }

    fn make_packet() -> MaintenancePacket {
        let before_bytes = b"before".to_vec();
        let after_bytes = b"after".to_vec();
        let proposal = MaintenancePatchProposal {
            patch_id: "patch".into(),
            proposer_role: "proposer".into(),
            relative_path: "src/example.rs".into(),
            before_digest: digest_bytes(&before_bytes),
            before_bytes,
            after_digest: digest_bytes(&after_bytes),
            after_bytes,
            requirements: requirements(),
            proposed_at: 10,
            expires_at: 100,
        };
        let evaluation = MaintenanceEvaluation {
            evaluation_id: "evaluation".into(),
            evaluator_role: "evaluator".into(),
            proposal_digest: proposal.digest().unwrap(),
            requirements: requirements(),
            test_results: REQUIRED_ADVERSARIAL_TESTS
                .iter()
                .map(|test_id| MaintenanceTestResult {
                    test_id: (*test_id).into(),
                    passed: true,
                })
                .collect(),
            accepted: true,
            evaluated_at: 11,
            expires_at: 90,
        };
        MaintenancePacket {
            proposal,
            evaluation,
        }
    }

    fn make_acceptance(packet: &MaintenancePacket) -> MaintenanceAcceptance {
        MaintenanceAcceptance {
            reviewer_role: "reviewer".into(),
            complete_packet_digest: packet.digest().unwrap(),
            accepted_at: 12,
            expires_at: 80,
        }
    }

    fn coordinator() -> MaintenanceCoordinator {
        MaintenanceCoordinator::new(requirements(), "evaluator", "reviewer").unwrap()
    }

    #[test]
    fn applies_once_and_rejects_replay() {
        let packet = make_packet();
        let acceptance = make_acceptance(&packet);
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        let first = runner
            .apply(&packet, Some(&acceptance), &mut executor, 20)
            .unwrap();
        assert_eq!(first.status, MaintenanceStatus::Applied);
        let second = runner
            .apply(&packet, Some(&acceptance), &mut executor, 20)
            .unwrap();
        assert_eq!(second.reason, Some(MaintenanceReason::ReplayedAcceptance));
    }

    #[test]
    fn missing_and_expired_evidence_quarantine() {
        let packet = make_packet();
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        assert_eq!(
            runner
                .apply(&packet, None, &mut executor, 20)
                .unwrap()
                .status,
            MaintenanceStatus::Quarantined
        );
        let mut expired = make_acceptance(&packet);
        expired.expires_at = 20;
        assert_eq!(
            runner
                .apply(&packet, Some(&expired), &mut executor, 20)
                .unwrap()
                .status,
            MaintenanceStatus::Quarantined
        );
        let mut early = make_acceptance(&packet);
        early.accepted_at = 10;
        assert_eq!(
            runner
                .apply(&packet, Some(&early), &mut executor, 20)
                .unwrap()
                .status,
            MaintenanceStatus::Quarantined
        );
    }

    #[test]
    fn substitution_and_path_escape_are_quarantined() {
        let mut packet = make_packet();
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        packet.proposal.requirements.policy_digest = "e".repeat(64);
        packet.evaluation.requirements.policy_digest = "e".repeat(64);
        packet.evaluation.proposal_digest = packet.proposal.digest().unwrap();
        let acceptance = make_acceptance(&packet);
        assert_eq!(
            runner
                .apply(&packet, Some(&acceptance), &mut executor, 20)
                .unwrap()
                .status,
            MaintenanceStatus::Quarantined
        );
        for path in ["../escape.rs", "/tmp/escape.rs", "a/../../escape.rs"] {
            packet = make_packet();
            packet.proposal.relative_path = path.into();
            assert!(packet.proposal.validate(20).is_err());
        }
    }

    #[test]
    fn failed_postcheck_rolls_back_and_failed_rollback_freezes() {
        let packet = make_packet();
        let acceptance = make_acceptance(&packet);
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        executor.corrupt_next_write = true;
        let result = runner
            .apply(&packet, Some(&acceptance), &mut executor, 20)
            .unwrap();
        assert_eq!(result.status, MaintenanceStatus::RolledBack);
        assert_eq!(
            executor.file(&packet.proposal.relative_path),
            Some(b"before".as_slice())
        );

        let packet = make_packet();
        let acceptance = make_acceptance(&packet);
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        executor.corrupt_next_write = true;
        executor.fail_rollback_writes = true;
        assert_eq!(
            runner
                .apply(&packet, Some(&acceptance), &mut executor, 20)
                .unwrap()
                .status,
            MaintenanceStatus::Frozen
        );
        let mut fresh = make_packet();
        fresh.proposal.patch_id = "fresh-patch".into();
        fresh.evaluation.proposal_digest = fresh.proposal.digest().unwrap();
        let fresh_acceptance = make_acceptance(&fresh);
        assert_eq!(
            runner
                .apply(&fresh, Some(&fresh_acceptance), &mut executor, 20)
                .unwrap()
                .status,
            MaintenanceStatus::Frozen
        );
    }

    #[test]
    fn changed_patch_cannot_reuse_evaluation_with_fresh_acceptance() {
        let mut packet = make_packet();
        packet.proposal.after_bytes = b"substituted".to_vec();
        packet.proposal.after_digest = digest_bytes(&packet.proposal.after_bytes);
        let acceptance = make_acceptance(&packet);
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        let result = runner
            .apply(&packet, Some(&acceptance), &mut executor, 20)
            .unwrap();
        assert_eq!(result.status, MaintenanceStatus::Quarantined);
        assert_eq!(executor.writes, 0);
        assert_eq!(
            executor.file(&packet.proposal.relative_path),
            Some(b"before".as_slice())
        );
    }

    #[test]
    fn empty_test_roster_is_rejected_before_change() {
        let mut packet = make_packet();
        packet.evaluation.test_results.clear();
        let acceptance = make_acceptance(&packet);
        let mut runner = coordinator();
        let mut executor = InMemoryMaintenanceExecutor::with_file(
            &packet.proposal.relative_path,
            packet.proposal.before_bytes.clone(),
        );
        let result = runner
            .apply(&packet, Some(&acceptance), &mut executor, 20)
            .unwrap();
        assert_eq!(result.status, MaintenanceStatus::Quarantined);
        assert_eq!(
            executor.file(&packet.proposal.relative_path),
            Some(b"before".as_slice())
        );
    }
}
