//! Immutable-base shadow/canary adaptation contract.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The record models the phase-3 controls without training, serving, traffic,
//! deployment, or promotion authority. A candidate may be proposed, but every
//! phase result must bind the frozen evaluator, policy, resource budget,
//! prediction lock, canary policy, and independent release authority.

use crate::{canonical_bytes, digest, valid_digest, Error, Result, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const SCHEMA_VERSION: &str = "security-alignment-os-adaptation-record-v1";
const CLAIM_CEILING: &str = "ControlledLocalShadowAdaptation";
const MAX_TEXT_LEN: usize = 256;

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_LEN && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AdaptationState {
    Shadow,
    Canary,
    CandidateApproved,
    ReleasedLocal,
    RolledBack,
    Frozen,
}

/// Evidence bundle supplied by an independent phase reviewer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptationEvidence {
    pub reviewer_id: String,
    pub promotion_authority_id: String,
    pub evaluator_digest: String,
    pub evidence_digest: String,
    pub stream_digest: String,
    pub resource_usage_digest: String,
    pub healthy: bool,
}

/// Immutable candidate and evaluation controls plus phase evidence digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptationRecord {
    pub schema_version: String,
    pub state_slice: String,
    pub claim_ceiling: String,
    pub candidate_id: String,
    pub proposer_id: String,
    pub base_digest: String,
    pub candidate_digest: String,
    pub training_data_manifest_digest: String,
    pub evaluator_digest: String,
    pub policy_digest: String,
    pub resource_budget_digest: String,
    pub evaluation_lock_digest: String,
    pub canary_policy_digest: String,
    pub promotion_authority_id: String,
    pub rollback_digest: String,
    pub state: AdaptationState,
    pub shadow_evidence_digest: Option<String>,
    pub canary_evidence_digest: Option<String>,
    pub promotion_evidence_digest: Option<String>,
    pub terminal_reason_digest: Option<String>,
    pub record_digest: String,
}

impl AdaptationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_id: impl Into<String>,
        proposer_id: impl Into<String>,
        base_digest: impl Into<String>,
        candidate_digest: impl Into<String>,
        training_data_manifest_digest: impl Into<String>,
        evaluator_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        resource_budget_digest: impl Into<String>,
        evaluation_lock_digest: impl Into<String>,
        canary_policy_digest: impl Into<String>,
        promotion_authority_id: impl Into<String>,
    ) -> Result<Self> {
        let mut record = Self {
            schema_version: SCHEMA_VERSION.into(),
            state_slice: STATE_SLICE.into(),
            claim_ceiling: CLAIM_CEILING.into(),
            candidate_id: candidate_id.into(),
            proposer_id: proposer_id.into(),
            base_digest: base_digest.into(),
            candidate_digest: candidate_digest.into(),
            training_data_manifest_digest: training_data_manifest_digest.into(),
            evaluator_digest: evaluator_digest.into(),
            policy_digest: policy_digest.into(),
            resource_budget_digest: resource_budget_digest.into(),
            evaluation_lock_digest: evaluation_lock_digest.into(),
            canary_policy_digest: canary_policy_digest.into(),
            promotion_authority_id: promotion_authority_id.into(),
            rollback_digest: String::new(),
            state: AdaptationState::Shadow,
            shadow_evidence_digest: None,
            canary_evidence_digest: None,
            promotion_evidence_digest: None,
            terminal_reason_digest: None,
            record_digest: String::new(),
        };
        record.rollback_digest = record.base_digest.clone();
        record.validate_body()?;
        record.record_digest = record.expected_digest()?;
        record.validate()?;
        Ok(record)
    }

    fn validate_body(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION
            || self.state_slice != STATE_SLICE
            || self.claim_ceiling != CLAIM_CEILING
            || !valid_text(&self.candidate_id)
            || !valid_text(&self.proposer_id)
            || !valid_text(&self.promotion_authority_id)
            || !valid_digest(&self.base_digest)
            || !valid_digest(&self.candidate_digest)
            || !valid_digest(&self.training_data_manifest_digest)
            || !valid_digest(&self.evaluator_digest)
            || !valid_digest(&self.policy_digest)
            || !valid_digest(&self.resource_budget_digest)
            || !valid_digest(&self.evaluation_lock_digest)
            || !valid_digest(&self.canary_policy_digest)
            || !valid_digest(&self.rollback_digest)
            || self.base_digest != self.rollback_digest
            || self.base_digest == self.candidate_digest
            || self
                .shadow_evidence_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .canary_evidence_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .promotion_evidence_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .terminal_reason_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || self.proposer_id == self.promotion_authority_id
        {
            return Err(Error::Invalid("adaptation record is malformed".into()));
        }
        match self.state {
            AdaptationState::Shadow => {
                if self.shadow_evidence_digest.is_some()
                    || self.canary_evidence_digest.is_some()
                    || self.promotion_evidence_digest.is_some()
                {
                    return Err(Error::Invalid(
                        "shadow state contains phase evidence".into(),
                    ));
                }
            }
            AdaptationState::Canary => {
                if self.shadow_evidence_digest.is_none()
                    || self.canary_evidence_digest.is_some()
                    || self.promotion_evidence_digest.is_some()
                {
                    return Err(Error::Invalid(
                        "canary state evidence is inconsistent".into(),
                    ));
                }
            }
            AdaptationState::CandidateApproved => {
                if self.shadow_evidence_digest.is_none()
                    || self.canary_evidence_digest.is_none()
                    || self.promotion_evidence_digest.is_some()
                {
                    return Err(Error::Invalid(
                        "approved candidate evidence is inconsistent".into(),
                    ));
                }
            }
            AdaptationState::ReleasedLocal => {
                if self.shadow_evidence_digest.is_none()
                    || self.canary_evidence_digest.is_none()
                    || self.promotion_evidence_digest.is_none()
                {
                    return Err(Error::Invalid(
                        "released candidate evidence is incomplete".into(),
                    ));
                }
            }
            AdaptationState::RolledBack | AdaptationState::Frozen => {
                if self.terminal_reason_digest.is_none() {
                    return Err(Error::Invalid(
                        "terminal adaptation reason is missing".into(),
                    ));
                }
            }
        }
        let evidence = [
            self.shadow_evidence_digest.as_ref(),
            self.canary_evidence_digest.as_ref(),
            self.promotion_evidence_digest.as_ref(),
        ];
        if evidence.iter().flatten().count()
            != evidence
                .iter()
                .flatten()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        {
            return Err(Error::Invalid(
                "adaptation phase evidence was reused".into(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String> {
        digest(&AdaptationIdentity {
            schema_version: &self.schema_version,
            state_slice: &self.state_slice,
            claim_ceiling: &self.claim_ceiling,
            candidate_id: &self.candidate_id,
            proposer_id: &self.proposer_id,
            base_digest: &self.base_digest,
            candidate_digest: &self.candidate_digest,
            training_data_manifest_digest: &self.training_data_manifest_digest,
            evaluator_digest: &self.evaluator_digest,
            policy_digest: &self.policy_digest,
            resource_budget_digest: &self.resource_budget_digest,
            evaluation_lock_digest: &self.evaluation_lock_digest,
            canary_policy_digest: &self.canary_policy_digest,
            promotion_authority_id: &self.promotion_authority_id,
            rollback_digest: &self.rollback_digest,
            state: self.state,
            shadow_evidence_digest: &self.shadow_evidence_digest,
            canary_evidence_digest: &self.canary_evidence_digest,
            promotion_evidence_digest: &self.promotion_evidence_digest,
            terminal_reason_digest: &self.terminal_reason_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_body()?;
        if !valid_digest(&self.record_digest) || self.record_digest != self.expected_digest()? {
            return Err(Error::Invalid("adaptation record digest mismatch".into()));
        }
        Ok(())
    }

    fn phase_evidence_valid(&self, evidence: &AdaptationEvidence) -> Result<()> {
        if !valid_text(&evidence.reviewer_id)
            || !valid_text(&evidence.promotion_authority_id)
            || !valid_digest(&evidence.evaluator_digest)
            || !valid_digest(&evidence.evidence_digest)
            || !valid_digest(&evidence.stream_digest)
            || !valid_digest(&evidence.resource_usage_digest)
            || evidence.reviewer_id == self.proposer_id
            || evidence.reviewer_id == evidence.promotion_authority_id
            || evidence.promotion_authority_id != self.promotion_authority_id
            || evidence.evaluator_digest != self.evaluator_digest
        {
            return Err(Error::Rejected(
                "adaptation evidence identity or control binding failed".into(),
            ));
        }
        if !evidence.healthy {
            return Err(Error::Quarantined(
                "unhealthy adaptation evidence requires freeze".into(),
            ));
        }
        Ok(())
    }

    pub fn record_shadow(&mut self, evidence: &AdaptationEvidence) -> Result<()> {
        if self.state != AdaptationState::Shadow {
            return Err(Error::Rejected("adaptation is not in shadow state".into()));
        }
        self.phase_evidence_valid(evidence)?;
        self.shadow_evidence_digest = Some(evidence.evidence_digest.clone());
        self.state = AdaptationState::Canary;
        self.refresh_digest()
    }

    pub fn record_canary(&mut self, evidence: &AdaptationEvidence) -> Result<()> {
        if self.state != AdaptationState::Canary {
            return Err(Error::Rejected("adaptation is not in canary state".into()));
        }
        self.phase_evidence_valid(evidence)?;
        if self.shadow_evidence_digest.as_deref() == Some(&evidence.evidence_digest) {
            return Err(Error::Rejected("canary evidence was reused".into()));
        }
        self.canary_evidence_digest = Some(evidence.evidence_digest.clone());
        self.state = AdaptationState::CandidateApproved;
        self.refresh_digest()
    }

    pub fn promote(&mut self, authority_id: &str, approval_digest: &str) -> Result<()> {
        if self.state != AdaptationState::CandidateApproved
            || authority_id != self.promotion_authority_id
            || !valid_digest(approval_digest)
        {
            return Err(Error::Rejected(
                "adaptation promotion is not independently authorized".into(),
            ));
        }
        self.promotion_evidence_digest = Some(approval_digest.into());
        self.state = AdaptationState::ReleasedLocal;
        self.refresh_digest()
    }

    pub fn rollback(&mut self, reason_digest: &str) -> Result<()> {
        if matches!(
            self.state,
            AdaptationState::RolledBack | AdaptationState::Frozen
        ) || !valid_digest(reason_digest)
        {
            return Err(Error::Rejected("adaptation rollback is unavailable".into()));
        }
        self.terminal_reason_digest = Some(reason_digest.into());
        self.state = AdaptationState::RolledBack;
        self.refresh_digest()
    }

    pub fn freeze(&mut self, reason_digest: &str) -> Result<()> {
        if self.state == AdaptationState::Frozen || !valid_digest(reason_digest) {
            return Err(Error::Rejected(
                "adaptation is already frozen or malformed".into(),
            ));
        }
        self.terminal_reason_digest = Some(reason_digest.into());
        self.state = AdaptationState::Frozen;
        self.refresh_digest()
    }

    fn refresh_digest(&mut self) -> Result<()> {
        self.record_digest = self.expected_digest()?;
        self.validate()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(self)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let record: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&record)? != bytes {
            return Err(Error::Journal(
                "adaptation record is not canonical JSON".into(),
            ));
        }
        record.validate()?;
        Ok(record)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(record) => Ok(record),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let record = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(record)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Serialize)]
struct AdaptationIdentity<'a> {
    schema_version: &'a str,
    state_slice: &'a str,
    claim_ceiling: &'a str,
    candidate_id: &'a str,
    proposer_id: &'a str,
    base_digest: &'a str,
    candidate_digest: &'a str,
    training_data_manifest_digest: &'a str,
    evaluator_digest: &'a str,
    policy_digest: &'a str,
    resource_budget_digest: &'a str,
    evaluation_lock_digest: &'a str,
    canary_policy_digest: &'a str,
    promotion_authority_id: &'a str,
    rollback_digest: &'a str,
    state: AdaptationState,
    shadow_evidence_digest: &'a Option<String>,
    canary_evidence_digest: &'a Option<String>,
    promotion_evidence_digest: &'a Option<String>,
    terminal_reason_digest: &'a Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: char) -> String {
        format!("{:064x}", value as u32)
    }

    fn record() -> AdaptationRecord {
        AdaptationRecord::new(
            "candidate-1",
            "proposer",
            digest('a'),
            digest('b'),
            digest('c'),
            digest('d'),
            digest('e'),
            digest('f'),
            digest('g'),
            digest('h'),
            "release-authority",
        )
        .expect("record")
    }

    fn evidence(
        evidence: char,
        stream: char,
        resource_usage: char,
        healthy: bool,
    ) -> AdaptationEvidence {
        AdaptationEvidence {
            reviewer_id: "reviewer".into(),
            promotion_authority_id: "release-authority".into(),
            evaluator_digest: digest('d'),
            evidence_digest: digest(evidence),
            stream_digest: digest(stream),
            resource_usage_digest: digest(resource_usage),
            healthy,
        }
    }

    #[test]
    fn adaptation_requires_independent_controls_and_phases() {
        let mut value = record();
        let mut proposer_evidence = evidence('i', 'j', 'k', true);
        proposer_evidence.reviewer_id = "proposer".into();
        assert!(value.record_shadow(&proposer_evidence).is_err());
        value
            .record_shadow(&evidence('i', 'j', 'k', true))
            .expect("shadow");
        value
            .record_canary(&evidence('l', 'm', 'n', true))
            .expect("canary");
        value
            .promote("release-authority", &digest('o'))
            .expect("promotion");
        assert_eq!(value.state, AdaptationState::ReleasedLocal);
    }

    #[test]
    fn unhealthy_evidence_does_not_advance_or_mutate() {
        let mut value = record();
        let before = value.clone();
        let unhealthy = evidence('i', 'j', 'k', false);
        assert!(matches!(
            value.record_shadow(&unhealthy),
            Err(Error::Quarantined(_))
        ));
        assert_eq!(value, before);
    }

    #[test]
    fn persistence_is_canonical_and_recoverable() {
        let value = record();
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("adaptation.json");
        value.save(&path).expect("save");
        assert_eq!(AdaptationRecord::load(&path).expect("load"), value);
        let bytes = std::fs::read(&path).expect("bytes");
        std::fs::write(path.with_extension("tmp"), bytes).expect("temporary");
        std::fs::remove_file(&path).expect("primary");
        assert_eq!(AdaptationRecord::recover(&path).expect("recover"), value);
    }
}
