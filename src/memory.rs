//! Caller-owned durable specialist memory with explicit consent on every access.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The file format is canonical JSON and stores only the selected tenant,
//! resource, grant binding, value and value digest. Consent grants are not
//! persisted; a caller must reconstruct and re-register an equivalent grant
//! after restart. This is local persistence, not encrypted storage or secure
//! deletion.

use crate::specialist::{ConsentGrant, SpecialistRegistry};
use crate::{canonical_bytes, digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryRecord {
    pub tenant_id: String,
    pub resource_id: String,
    pub grant_id: String,
    pub value: Value,
    pub value_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MemoryDocument {
    version: u8,
    records: Vec<MemoryRecord>,
}

#[derive(Clone, Debug)]
pub struct PersistentMemory {
    path: PathBuf,
    records: BTreeMap<(String, String), MemoryRecord>,
}

fn expected_grant_id(grant: &ConsentGrant) -> Result<String> {
    digest(&(
        grant.tenant_id.clone(),
        grant.specialist_id.clone(),
        grant.resource_ids.clone(),
        grant.issued_at,
        grant.expires_at,
    ))
}

fn validate_record(record: &MemoryRecord) -> Result<()> {
    if record.tenant_id.is_empty()
        || record.resource_id.is_empty()
        || !valid_digest(&record.grant_id)
        || !valid_digest(&record.value_digest)
        || digest(&record.value)? != record.value_digest
    {
        return Err(Error::Persistence(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid durable memory record",
        )));
    }
    Ok(())
}

impl PersistentMemory {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Self::load_existing(path);
        }
        let temporary = path.with_extension("tmp");
        if temporary.exists() {
            let memory = Self::load_existing(temporary)?;
            fs::rename(&memory.path, &path)?;
            return Ok(Self { path, ..memory });
        }
        Ok(Self {
            path,
            records: BTreeMap::new(),
        })
    }

    fn load_existing(path: PathBuf) -> Result<Self> {
        let bytes = fs::read(&path)?;
        let document: MemoryDocument = serde_json::from_slice(&bytes)?;
        if document.version != FORMAT_VERSION || canonical_bytes(&document)? != bytes {
            return Err(Error::Persistence(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "memory file is noncanonical or unsupported",
            )));
        }
        let mut records = BTreeMap::new();
        for record in document.records {
            validate_record(&record)?;
            let key = (record.tenant_id.clone(), record.resource_id.clone());
            if records.insert(key, record).is_some() {
                return Err(Error::Persistence(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate durable memory key",
                )));
            }
        }
        Ok(Self { path, records })
    }

    pub fn recover(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() || path.with_extension("tmp").exists() {
            return Self::open(path);
        }
        Ok(Self {
            path: path.to_path_buf(),
            records: BTreeMap::new(),
        })
    }

    fn check_consent(
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<()> {
        grant.validate()?;
        if !grant.active(now)
            || !grant.allows(resource_id)
            || expected_grant_id(grant)? != grant.grant_id
            || registry.resolve(&grant.specialist_id, now).is_none()
        {
            return Err(Error::Rejected("consent or specialist is invalid".into()));
        }
        Ok(())
    }

    pub fn put(
        &mut self,
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        value: Value,
        now: u64,
    ) -> Result<String> {
        Self::check_consent(registry, grant, resource_id, now)?;
        let value_digest = digest(&value)?;
        let record = MemoryRecord {
            tenant_id: grant.tenant_id.clone(),
            resource_id: resource_id.into(),
            grant_id: grant.grant_id.clone(),
            value,
            value_digest: value_digest.clone(),
        };
        self.records.insert(
            (record.tenant_id.clone(), record.resource_id.clone()),
            record,
        );
        self.save()?;
        Ok(value_digest)
    }

    pub fn retrieve(
        &self,
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<Value> {
        Self::check_consent(registry, grant, resource_id, now)?;
        let record = self
            .records
            .get(&(grant.tenant_id.clone(), resource_id.into()))
            .ok_or_else(|| Error::Invalid("resource not found".into()))?;
        if record.grant_id != grant.grant_id {
            return Err(Error::Rejected("memory grant binding mismatch".into()));
        }
        validate_record(record)?;
        Ok(record.value.clone())
    }

    pub fn delete(
        &mut self,
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<bool> {
        Self::check_consent(registry, grant, resource_id, now)?;
        let key = (grant.tenant_id.clone(), resource_id.into());
        let Some(record) = self.records.get(&key) else {
            return Ok(false);
        };
        if record.grant_id != grant.grant_id {
            return Err(Error::Rejected("memory grant binding mismatch".into()));
        }
        self.records.remove(&key);
        self.save()?;
        Ok(true)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn save(&self) -> Result<()> {
        for record in self.records.values() {
            validate_record(record)?;
        }
        let document = MemoryDocument {
            version: FORMAT_VERSION,
            records: self.records.values().cloned().collect(),
        };
        let bytes = canonical_bytes(&document)?;
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, &self.path)?;
        Ok(())
    }
}
