//! Local artifact manifests and fail-closed evidence lifecycle.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module binds a named artifact record to exact subject and source
//! digests, a caller-supplied provenance digest, and a declared custody and
//! retention interval.  Registry transitions are local pure-data checks.  The
//! role fields are assertions supplied by the caller; they are not signatures,
//! authenticated identities, or proof of external custody.

use crate::{digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactManifest {
    /// Stable local identifier for this manifest.
    pub artifact_id: String,
    /// SHA-256 digest of the exact subject bytes the evidence concerns.
    pub subject_digest: String,
    /// SHA-256 digest of the exact source or producer bytes.
    pub source_digest: String,
    /// Caller-declared license identifier or notice reference.
    pub license: String,
    /// SHA-256 digest of the caller-supplied provenance record.
    pub provenance_digest: String,
    /// Caller-declared root holding retained bytes.
    pub custody_root: String,
    /// Inclusive beginning of the permitted retention interval.
    pub retention_start: u64,
    /// Exclusive end of the permitted retention interval.
    pub retention_until: u64,
}

impl ArtifactManifest {
    pub fn validate(&self) -> Result<()> {
        if self.artifact_id.trim().is_empty()
            || self.license.trim().is_empty()
            || self.custody_root.trim().is_empty()
        {
            return Err(Error::Invalid(
                "artifact identity, license, and custody root are required".into(),
            ));
        }
        if self
            .artifact_id
            .chars()
            .any(|character| character.is_control())
            || self.license.chars().any(|character| character.is_control())
            || self
                .custody_root
                .chars()
                .any(|character| character.is_control())
        {
            return Err(Error::Invalid(
                "artifact manifest fields cannot contain control characters".into(),
            ));
        }
        if !valid_digest(&self.subject_digest)
            || !valid_digest(&self.source_digest)
            || !valid_digest(&self.provenance_digest)
        {
            return Err(Error::Invalid(
                "subject, source, and provenance digests must be lowercase SHA-256".into(),
            ));
        }
        if self.retention_until <= self.retention_start {
            return Err(Error::Invalid(
                "retention interval must have a positive duration".into(),
            ));
        }
        Ok(())
    }

    pub fn active(&self, now: u64) -> bool {
        self.retention_start <= now && now < self.retention_until
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }

    pub fn binds_subject(&self, subject_digest: &str) -> bool {
        self.subject_digest == subject_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ArtifactStatus {
    Quarantined,
    Accepted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRecord {
    pub manifest: ArtifactManifest,
    /// Caller-asserted role that submitted the artifact.
    pub operator_id: String,
    /// Caller-asserted role that performed the local validation.
    pub validator_id: String,
    /// Caller-asserted independent review role, present only after acceptance.
    pub reviewer_id: Option<String>,
    pub status: ArtifactStatus,
    pub accepted_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRegistry {
    records: BTreeMap<String, ArtifactRecord>,
}

fn validate_role(role: &str, field: &str) -> Result<()> {
    if role.trim().is_empty() || role.chars().any(|character| character.is_control()) {
        return Err(Error::Invalid(format!(
            "{field} must be a non-empty role assertion"
        )));
    }
    Ok(())
}

fn validate_distinct_roles(operator_id: &str, validator_id: &str) -> Result<()> {
    validate_role(operator_id, "operator")?;
    validate_role(validator_id, "validator")?;
    if operator_id == validator_id {
        return Err(Error::Rejected(
            "operator and validator roles must be distinct".into(),
        ));
    }
    Ok(())
}

impl ArtifactRegistry {
    /// Place a validated artifact into quarantine.  Quarantine does not make
    /// the subject usable; acceptance is a separate transition.
    pub fn quarantine(
        &mut self,
        manifest: ArtifactManifest,
        operator_id: impl Into<String>,
        validator_id: impl Into<String>,
    ) -> Result<()> {
        manifest.validate()?;
        let operator_id = operator_id.into();
        let validator_id = validator_id.into();
        validate_distinct_roles(&operator_id, &validator_id)?;
        if self.records.contains_key(&manifest.artifact_id) {
            return Err(Error::Rejected("artifact identifier already exists".into()));
        }
        let artifact_id = manifest.artifact_id.clone();
        self.records.insert(
            artifact_id,
            ArtifactRecord {
                manifest,
                operator_id,
                validator_id,
                reviewer_id: None,
                status: ArtifactStatus::Quarantined,
                accepted_at: None,
                revoked_at: None,
            },
        );
        Ok(())
    }

    /// Accept only the quarantined record whose subject digest exactly equals
    /// the digest supplied at review time and whose retention interval is live.
    pub fn accept(
        &mut self,
        artifact_id: &str,
        subject_digest: &str,
        reviewer_id: impl Into<String>,
        now: u64,
    ) -> Result<()> {
        if !valid_digest(subject_digest) {
            return Err(Error::Invalid("review subject digest is malformed".into()));
        }
        let reviewer_id = reviewer_id.into();
        validate_role(&reviewer_id, "reviewer")?;
        let record = self
            .records
            .get_mut(artifact_id)
            .ok_or_else(|| Error::Invalid("artifact not found".into()))?;
        if record.status != ArtifactStatus::Quarantined {
            return Err(Error::Rejected(
                "only quarantined artifacts can be accepted".into(),
            ));
        }
        if !record.manifest.binds_subject(subject_digest) {
            return Err(Error::Rejected("artifact subject binding mismatch".into()));
        }
        if !record.manifest.active(now) {
            return Err(Error::Rejected(
                "artifact is outside its retention interval".into(),
            ));
        }
        if reviewer_id == record.operator_id || reviewer_id == record.validator_id {
            return Err(Error::Rejected(
                "reviewer role must be distinct from operator and validator".into(),
            ));
        }
        record.reviewer_id = Some(reviewer_id);
        record.accepted_at = Some(now);
        record.status = ArtifactStatus::Accepted;
        Ok(())
    }

    /// Revoke a quarantined or accepted record after checking its exact
    /// subject binding.  Revocation is terminal for this local record.
    pub fn revoke(&mut self, artifact_id: &str, subject_digest: &str, now: u64) -> Result<()> {
        if !valid_digest(subject_digest) {
            return Err(Error::Invalid("revoke subject digest is malformed".into()));
        }
        let record = self
            .records
            .get_mut(artifact_id)
            .ok_or_else(|| Error::Invalid("artifact not found".into()))?;
        if record.status == ArtifactStatus::Revoked {
            return Err(Error::Rejected("artifact is already revoked".into()));
        }
        if !record.manifest.binds_subject(subject_digest) {
            return Err(Error::Rejected("artifact subject binding mismatch".into()));
        }
        record.status = ArtifactStatus::Revoked;
        record.revoked_at = Some(now);
        Ok(())
    }

    pub fn get(&self, artifact_id: &str) -> Option<&ArtifactRecord> {
        self.records.get(artifact_id)
    }

    pub fn is_valid(&self, artifact_id: &str, subject_digest: &str, now: u64) -> bool {
        let Some(record) = self.records.get(artifact_id) else {
            return false;
        };
        record.manifest.validate().is_ok()
            && record.status == ArtifactStatus::Accepted
            && record.reviewer_id.is_some()
            && record.manifest.active(now)
            && record.manifest.binds_subject(subject_digest)
            && validate_distinct_roles(&record.operator_id, &record.validator_id).is_ok()
            && record.reviewer_id.as_deref().is_some_and(|reviewer| {
                validate_role(reviewer, "reviewer").is_ok()
                    && reviewer != record.operator_id
                    && reviewer != record.validator_id
            })
    }

    pub fn require_valid(
        &self,
        artifact_id: &str,
        subject_digest: &str,
        now: u64,
    ) -> Result<&ArtifactRecord> {
        if !self.is_valid(artifact_id, subject_digest, now) {
            return Err(Error::Rejected(
                "artifact evidence is absent, stale, revoked, or subject-mismatched".into(),
            ));
        }
        self.records
            .get(artifact_id)
            .ok_or_else(|| Error::Rejected("artifact evidence is unavailable".into()))
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_with(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn manifest() -> ArtifactManifest {
        ArtifactManifest {
            artifact_id: "artifact-1".into(),
            subject_digest: digest_with('a'),
            source_digest: digest_with('b'),
            license: "MIT".into(),
            provenance_digest: digest_with('c'),
            custody_root: "/tmp/local-custody".into(),
            retention_start: 10,
            retention_until: 20,
        }
    }

    #[test]
    fn manifest_validation_is_fail_closed() {
        let mut invalid = manifest();
        invalid.subject_digest = "not-a-digest".into();
        assert!(invalid.validate().is_err());

        let mut invalid = manifest();
        invalid.retention_until = invalid.retention_start;
        assert!(invalid.validate().is_err());

        let mut invalid = manifest();
        invalid.custody_root = "\n".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn lifecycle_requires_exact_subject_and_distinct_roles() {
        let item = manifest();
        let subject = item.subject_digest.clone();
        let mut registry = ArtifactRegistry::default();
        assert!(registry
            .quarantine(item.clone(), "operator", "validator")
            .is_ok());
        assert!(!registry.is_valid("artifact-1", &subject, 12));
        assert!(registry
            .accept("artifact-1", &digest_with('d'), "reviewer", 12)
            .is_err());
        assert!(registry
            .accept("artifact-1", &subject, "validator", 12)
            .is_err());
        assert!(registry
            .accept("artifact-1", &subject, "reviewer", 12)
            .is_ok());
        assert!(registry.is_valid("artifact-1", &subject, 12));
        assert!(!registry.is_valid("artifact-1", &digest_with('d'), 12));
        assert!(registry.revoke("artifact-1", &subject, 13).is_ok());
        assert!(!registry.is_valid("artifact-1", &subject, 13));
        assert!(registry.revoke("artifact-1", &subject, 14).is_err());
    }

    #[test]
    fn acceptance_requires_live_retention_and_unique_manifest_id() {
        let item = manifest();
        let subject = item.subject_digest.clone();
        let mut registry = ArtifactRegistry::default();
        assert!(registry
            .quarantine(item.clone(), "operator", "validator")
            .is_ok());
        assert!(registry
            .quarantine(item, "operator-2", "validator-2")
            .is_err());
        assert!(registry
            .accept("artifact-1", &subject, "reviewer", 20)
            .is_err());
        assert!(registry.require_valid("artifact-1", &subject, 12).is_err());
    }

    #[test]
    fn manifest_digest_is_canonical_and_changes_with_subject() {
        let item = manifest();
        let first = item.digest().expect("valid manifest");
        let second = item.digest().expect("valid manifest");
        assert_eq!(first, second);
        let mut changed = item;
        changed.subject_digest = digest_with('d');
        assert_ne!(first, changed.digest().expect("valid manifest"));
    }
}
