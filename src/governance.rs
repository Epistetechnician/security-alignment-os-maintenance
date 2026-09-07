//! Shadow/canary release records; no model promotion or deployment.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{canonical_bytes, digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReleaseState {
    Shadow,
    Canary,
    ReleasedLocal,
    Frozen,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseRegistry {
    records: BTreeMap<String, (CandidateUpdate, ReleaseState)>,
    used_evidence: BTreeMap<String, BTreeSet<String>>,
}

impl ReleaseRegistry {
    pub fn validate(&self) -> Result<()> {
        if self.records.len() != self.used_evidence.len() {
            return Err(Error::Invalid(
                "release evidence index is inconsistent".into(),
            ));
        }
        for (id, (candidate, state)) in &self.records {
            if id != &candidate.candidate_id {
                return Err(Error::Invalid("release candidate key mismatch".into()));
            }
            candidate.validate()?;
            let used = self
                .used_evidence
                .get(id)
                .ok_or_else(|| Error::Invalid("release evidence record is missing".into()))?;
            if !used.contains(&candidate.evidence_digest)
                && !matches!(state, ReleaseState::Shadow | ReleaseState::Frozen)
            {
                return Err(Error::Invalid(
                    "release state lacks initial candidate evidence".into(),
                ));
            }
            match state {
                ReleaseState::Shadow if !used.is_empty() => {
                    return Err(Error::Invalid("shadow release has phase evidence".into()))
                }
                ReleaseState::Canary if used.len() != 1 => {
                    return Err(Error::Invalid(
                        "canary release evidence count is invalid".into(),
                    ))
                }
                ReleaseState::ReleasedLocal if used.len() != 2 => {
                    return Err(Error::Invalid(
                        "local release requires distinct phase evidence".into(),
                    ))
                }
                ReleaseState::Frozen if used.len() > 2 => {
                    return Err(Error::Invalid(
                        "frozen release evidence count is invalid".into(),
                    ))
                }
                _ => {}
            }
            if used.iter().any(|evidence| !valid_digest(evidence)) {
                return Err(Error::Invalid(
                    "release evidence digest is malformed".into(),
                ));
            }
        }
        Ok(())
    }

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
        self.validate()?;
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
        self.validate()?;
        Ok(())
    }
    pub fn freeze(&mut self, id: &str) -> Result<()> {
        let (_, state) = self
            .records
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("unknown candidate".into()))?;
        if *state == ReleaseState::Frozen {
            return Err(Error::Rejected("candidate is already frozen".into()));
        }
        *state = ReleaseState::Frozen;
        self.validate()?;
        Ok(())
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
        let registry: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&registry)? != bytes {
            return Err(Error::Journal(
                "release bytes are not canonical JSON".into(),
            ));
        }
        registry.validate()?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(registry) => Ok(registry),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let registry = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(registry)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> CandidateUpdate {
        CandidateUpdate {
            candidate_id: "candidate-1".into(),
            base_digest: "a".repeat(64),
            candidate_digest: "b".repeat(64),
            rollback_digest: "a".repeat(64),
            evidence_digest: "c".repeat(64),
        }
    }

    #[test]
    fn lifecycle_evidence_cardinality_is_validated() {
        let mut registry = ReleaseRegistry::default();
        registry.propose(candidate()).expect("propose");
        registry.freeze("candidate-1").expect("freeze");
        registry.validate().expect("frozen validation");

        let mut active = ReleaseRegistry::default();
        active.propose(candidate()).expect("propose");
        active
            .advance("candidate-1", &"c".repeat(64))
            .expect("canary");
        active
            .advance("candidate-1", &"d".repeat(64))
            .expect("release");
        active.validate().expect("release validation");
        assert!(active.advance("candidate-1", &"e".repeat(64)).is_err());
    }

    #[test]
    fn persistence_rejects_noncanonical_and_recovers_temp() {
        let mut registry = ReleaseRegistry::default();
        registry.propose(candidate()).expect("propose");
        registry
            .advance("candidate-1", &"c".repeat(64))
            .expect("canary");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("release.json");
        registry.save(&path).expect("save");
        assert_eq!(ReleaseRegistry::load(&path).expect("load"), registry);

        let mut bytes = std::fs::read(&path).expect("read");
        let tamper_index = bytes.len() - 2;
        bytes[tamper_index] = b' ';
        std::fs::write(&path, bytes).expect("tamper");
        assert!(ReleaseRegistry::load(&path).is_err());

        std::fs::write(
            path.with_extension("tmp"),
            canonical_bytes(&registry).expect("canonical"),
        )
        .expect("temporary snapshot");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(ReleaseRegistry::recover(&path).expect("recover"), registry);
    }
}
