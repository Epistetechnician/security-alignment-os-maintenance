//! Caller-owned custody-root and retention records.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! These records describe a future external custody boundary without storing
//! raw bytes or private locators. The registry validates declared lifecycle
//! relationships and canonical persistence only; it cannot authenticate an
//! owner, inspect filesystem permissions, or enforce deletion.

use crate::{canonical_bytes, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const STATE_SLICE: &str = "security-alignment-os-foundation-v1";
pub const MAX_RAW_RETENTION_SECONDS: u64 = 72 * 60 * 60;

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(|character| character.is_control())
}

/// A declaration for an owner-only external custody root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRoot {
    pub root_id: String,
    pub owner_id: String,
    /// Digest of the root declaration; the locator itself is never retained.
    pub root_digest: String,
    /// Unix mode assertion required by the contract.
    pub mode: u32,
    pub external_to_repository: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub raw_retention_until: u64,
}

impl CustodyRoot {
    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.root_id, 128)
            || !valid_text(&self.owner_id, 256)
            || !valid_digest(&self.root_digest)
            || self.mode != 0o700
            || !self.external_to_repository
            || self.created_at >= self.expires_at
            || self.raw_retention_until < self.created_at
            || self.raw_retention_until > self.expires_at
            || self.raw_retention_until - self.created_at > MAX_RAW_RETENTION_SECONDS
        {
            return Err(Error::Invalid(
                "custody root declaration is malformed".into(),
            ));
        }
        Ok(())
    }

    pub fn active(&self, now: u64) -> bool {
        self.validate().is_ok() && self.created_at <= now && now < self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CustodyStatus {
    Active,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRecord {
    pub custody_id: String,
    pub root: CustodyRoot,
    pub artifact_digest: String,
    /// Owner assertion that declared the record.
    pub declared_by: String,
    /// Separate local validator assertion.
    pub validator_id: String,
    pub status: CustodyStatus,
    pub deleted_at: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRegistry {
    records: BTreeMap<String, CustodyRecord>,
}

impl CustodyRegistry {
    fn validate_record(key: &str, record: &CustodyRecord) -> Result<()> {
        if key != record.custody_id
            || !valid_text(&record.custody_id, 128)
            || !valid_digest(&record.artifact_digest)
            || record.declared_by != record.root.owner_id
            || !valid_text(&record.declared_by, 256)
            || !valid_text(&record.validator_id, 256)
            || record.declared_by == record.validator_id
        {
            return Err(Error::Invalid("custody record binding is malformed".into()));
        }
        record.root.validate()?;
        match record.status {
            CustodyStatus::Active if record.deleted_at.is_some() => Err(Error::Invalid(
                "active custody record cannot have a deletion time".into(),
            )),
            CustodyStatus::Deleted => {
                let deleted_at = record.deleted_at.ok_or_else(|| {
                    Error::Invalid("deleted custody record lacks deletion time".into())
                })?;
                if deleted_at < record.root.created_at {
                    return Err(Error::Invalid(
                        "custody deletion predates root creation".into(),
                    ));
                }
                Ok(())
            }
            CustodyStatus::Active => Ok(()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        for (key, record) in &self.records {
            Self::validate_record(key, record)?;
        }
        Ok(())
    }

    /// Declares a record under the root owner identity and a separate
    /// validator assertion.
    pub fn declare(
        &mut self,
        custody_id: impl Into<String>,
        root: CustodyRoot,
        artifact_digest: impl Into<String>,
        declared_by: impl Into<String>,
        validator_id: impl Into<String>,
    ) -> Result<()> {
        root.validate()?;
        let record = CustodyRecord {
            custody_id: custody_id.into(),
            root,
            artifact_digest: artifact_digest.into(),
            declared_by: declared_by.into(),
            validator_id: validator_id.into(),
            status: CustodyStatus::Active,
            deleted_at: None,
        };
        Self::validate_record(&record.custody_id, &record)?;
        if self.records.contains_key(&record.custody_id) {
            return Err(Error::Rejected("custody identity already exists".into()));
        }
        self.records.insert(record.custody_id.clone(), record);
        Ok(())
    }

    pub fn require_active(
        &self,
        custody_id: &str,
        artifact_digest: &str,
        now: u64,
    ) -> Result<&CustodyRecord> {
        if !valid_digest(artifact_digest) {
            return Err(Error::Invalid(
                "custody artifact digest is malformed".into(),
            ));
        }
        let record = self
            .records
            .get(custody_id)
            .ok_or_else(|| Error::Quarantined("custody record is unavailable".into()))?;
        if record.status != CustodyStatus::Active
            || !record.root.active(now)
            || record.artifact_digest != artifact_digest
        {
            return Err(Error::Rejected(
                "custody record is inactive or digest-mismatched".into(),
            ));
        }
        Ok(record)
    }

    pub fn mark_deleted(&mut self, custody_id: &str, owner_id: &str, now: u64) -> Result<()> {
        let record = self
            .records
            .get_mut(custody_id)
            .ok_or_else(|| Error::Invalid("custody record is unavailable".into()))?;
        if record.status != CustodyStatus::Active {
            return Err(Error::Rejected("custody record is already deleted".into()));
        }
        if owner_id != record.root.owner_id {
            return Err(Error::Rejected(
                "only the declared owner may delete custody".into(),
            ));
        }
        if now < record.root.created_at {
            return Err(Error::Rejected(
                "custody deletion time is before creation".into(),
            ));
        }
        record.status = CustodyStatus::Deleted;
        record.deleted_at = Some(now);
        Ok(())
    }

    pub fn get(&self, custody_id: &str) -> Option<&CustodyRecord> {
        self.records.get(custody_id)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
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
                "custody bytes are not canonical JSON".into(),
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

    fn root() -> CustodyRoot {
        CustodyRoot {
            root_id: "root-1".into(),
            owner_id: "owner".into(),
            root_digest: "a".repeat(64),
            mode: 0o700,
            external_to_repository: true,
            created_at: 10,
            expires_at: 100,
            raw_retention_until: 90,
        }
    }

    #[test]
    fn owner_declared_custody_is_bound_and_deletion_is_terminal() {
        let artifact_digest = "b".repeat(64);
        let mut registry = CustodyRegistry::default();
        registry
            .declare(
                "custody-1",
                root(),
                artifact_digest.clone(),
                "owner",
                "validator",
            )
            .expect("declare");
        assert!(registry
            .require_active("custody-1", &artifact_digest, 20)
            .is_ok());
        assert!(registry
            .require_active("custody-1", &"c".repeat(64), 20)
            .is_err());
        assert!(registry.mark_deleted("custody-1", "other", 30).is_err());
        registry
            .mark_deleted("custody-1", "owner", 30)
            .expect("delete");
        assert!(registry
            .require_active("custody-1", &artifact_digest, 30)
            .is_err());
        assert!(registry.mark_deleted("custody-1", "owner", 31).is_err());
    }

    #[test]
    fn malformed_roots_and_duplicate_records_fail_closed() {
        let artifact_digest = "b".repeat(64);
        let mut registry = CustodyRegistry::default();
        let mut invalid = root();
        invalid.mode = 0o755;
        assert!(registry
            .declare(
                "custody-1",
                invalid,
                artifact_digest.clone(),
                "owner",
                "validator",
            )
            .is_err());
        registry
            .declare("custody-1", root(), artifact_digest, "owner", "validator")
            .expect("declare");
        assert!(registry
            .declare("custody-1", root(), "b".repeat(64), "owner", "validator-2",)
            .is_err());
    }

    #[test]
    fn registry_round_trip_and_recovery_are_canonical() {
        let mut registry = CustodyRegistry::default();
        registry
            .declare("custody-1", root(), "b".repeat(64), "owner", "validator")
            .expect("declare");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("custody.json");
        registry.save(&path).expect("save");
        assert_eq!(CustodyRegistry::load(&path).expect("load"), registry);
        let bytes = crate::canonical_bytes(&registry).expect("canonical");
        std::fs::write(path.with_extension("tmp"), bytes).expect("temp");
        std::fs::remove_file(&path).expect("remove");
        assert_eq!(CustodyRegistry::recover(&path).expect("recover"), registry);
    }
}
