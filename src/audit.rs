//! Canonical caller-owned runtime audit persistence.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{canonical_bytes, digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_METADATA_FIELDS: usize = 8;

fn validate_metadata(metadata: &BTreeMap<String, String>) -> Result<()> {
    if metadata.is_empty() || metadata.len() > MAX_METADATA_FIELDS {
        return Err(Error::Journal(
            "audit metadata field count is invalid".into(),
        ));
    }
    for (key, value) in metadata {
        if key.is_empty()
            || key.len() > 64
            || key.chars().any(char::is_control)
            || value.is_empty()
            || value.len() > 256
            || value.chars().any(char::is_control)
        {
            return Err(Error::Journal("audit metadata field is malformed".into()));
        }
        match key.as_str() {
            "event" => {
                if !matches!(
                    value.as_str(),
                    "read" | "write" | "freeze" | "kill" | "rollback"
                ) {
                    return Err(Error::Journal("audit event is not allowlisted".into()));
                }
            }
            "candidate_digest"
            | "decision_digest"
            | "policy_digest"
            | "capability_token_id"
            | "state_digest"
            | "reason_digest" => {
                if !valid_digest(value) {
                    return Err(Error::Journal("audit digest field is malformed".into()));
                }
            }
            _ => {
                return Err(Error::Journal(
                    "audit metadata key is not allowlisted".into(),
                ))
            }
        }
    }
    if !metadata.contains_key("event") {
        return Err(Error::Journal("audit event field is missing".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub previous_digest: String,
    pub metadata: BTreeMap<String, String>,
    pub entry_digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditJournal {
    pub entries: Vec<AuditEntry>,
}

impl AuditJournal {
    pub fn from_records(records: &[BTreeMap<String, String>]) -> Result<Self> {
        let mut journal = Self::default();
        for metadata in records {
            validate_metadata(metadata)?;
            let sequence = journal.entries.len() as u64;
            let previous_digest = journal
                .entries
                .last()
                .map(|entry| entry.entry_digest.clone())
                .unwrap_or_else(|| "0".repeat(64));
            let entry_digest = digest(&(sequence, &previous_digest, metadata))?;
            journal.entries.push(AuditEntry {
                sequence,
                previous_digest,
                metadata: metadata.clone(),
                entry_digest,
            });
        }
        journal.validate()?;
        Ok(journal)
    }
    pub fn validate(&self) -> Result<()> {
        let mut previous = "0".repeat(64);
        for (index, entry) in self.entries.iter().enumerate() {
            if validate_metadata(&entry.metadata).is_err()
                || entry.sequence != index as u64
                || entry.previous_digest != previous
                || !valid_digest(&entry.previous_digest)
                || !valid_digest(&entry.entry_digest)
                || digest(&(entry.sequence, &entry.previous_digest, &entry.metadata))?
                    != entry.entry_digest
            {
                return Err(Error::Journal("invalid audit chain".into()));
            }
            previous = entry.entry_digest.clone();
        }
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
        let journal: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&journal)? != bytes {
            return Err(Error::Journal("audit bytes are not canonical JSON".into()));
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
