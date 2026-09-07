//! Shadow/canary release records; no model promotion or deployment.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{digest, valid_digest, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateUpdate {
    pub candidate_id: String,
    pub base_digest: String,
    pub candidate_digest: String,
    pub rollback_digest: String,
    pub evidence_digest: String,
}

impl CandidateUpdate {
    pub fn validate(&self) -> Result<()> {
        if self.candidate_id.is_empty()
            || !valid_digest(&self.base_digest)
            || !valid_digest(&self.candidate_digest)
            || !valid_digest(&self.rollback_digest)
            || !valid_digest(&self.evidence_digest)
            || self.base_digest == self.candidate_digest
            || self.base_digest != self.rollback_digest
        {
            return Err(Error::Invalid("invalid immutable-base candidate".into()));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(&(
            &self.candidate_id,
            &self.base_digest,
            &self.candidate_digest,
            &self.rollback_digest,
            &self.evidence_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseState {
    Shadow,
    Canary,
    ReleasedLocal,
    Frozen,
}

#[derive(Default)]
pub struct ReleaseRegistry {
    records: BTreeMap<String, (CandidateUpdate, ReleaseState)>,
    used_evidence: BTreeMap<String, BTreeSet<String>>,
}

impl ReleaseRegistry {
    pub fn propose(&mut self, candidate: CandidateUpdate) -> Result<()> {
        candidate.validate()?;
        if self.records.contains_key(&candidate.candidate_id) {
            return Err(Error::Rejected("candidate identity already exists".into()));
        }
        let candidate_id = candidate.candidate_id.clone();
        self.records
            .insert(candidate_id.clone(), (candidate, ReleaseState::Shadow));
        if !self.records.contains_key(&candidate_id) {
            return Err(Error::Invalid("candidate was not recorded".into()));
        }
        self.used_evidence.insert(candidate_id, BTreeSet::new());
        Ok(())
    }
    pub fn state(&self, id: &str) -> Option<ReleaseState> {
        self.records.get(id).map(|(_, state)| *state)
    }
    pub fn advance(&mut self, id: &str, evidence_digest: &str) -> Result<()> {
        let (candidate, state) = self
            .records
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("unknown candidate".into()))?;
        if candidate.evidence_digest != evidence_digest
            && (*state != ReleaseState::Canary
                || !valid_digest(evidence_digest)
                || evidence_digest == candidate.evidence_digest)
        {
            return Err(Error::Rejected("phase evidence mismatch".into()));
        }
        let next = match state {
            ReleaseState::Shadow => ReleaseState::Canary,
            ReleaseState::Canary => ReleaseState::ReleasedLocal,
            _ => return Err(Error::Rejected("terminal release state".into())),
        };
        let used = self
            .used_evidence
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("candidate evidence state missing".into()))?;
        if !used.insert(evidence_digest.into()) {
            return Err(Error::Rejected("phase evidence already used".into()));
        }
        *state = next;
        Ok(())
    }
    pub fn freeze(&mut self, id: &str) -> Result<()> {
        let (_, state) = self
            .records
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("unknown candidate".into()))?;
        *state = ReleaseState::Frozen;
        Ok(())
    }
}
