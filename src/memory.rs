//! Caller-owned durable specialist memory with explicit consent on every access.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The file format is canonical JSON and stores only the selected tenant,
//! resource, grant binding, value and value digest. Consent grants and
//! revocations live in a separate caller-owned `ConsentRegistry` snapshot that
//! callers must recover before access. Persistent consent handles serialize
//! consent updates with each gated memory effect, but neither file is
//! authenticated or protected against rollback. Memory is plaintext and
//! deletion is logical. A per-file lock serializes memory operations from
//! cooperating local handles and processes; each operation reloads the latest
//! snapshot while holding the lock. On Unix, snapshots are owner-only; writes
//! use a synced temporary file and recovery promotes a validated pending one.

use crate::persistence::{acquire_file_lock, save_atomic_snapshot_locked, sync_parent_directory};
use crate::specialist::{ConsentGrant, ConsentRegistry, SpecialistRegistry};
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
        let _lock = match acquire_file_lock(&path, "persistent memory") {
            Ok(lock) => lock,
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    records: BTreeMap::new(),
                });
            }
            Err(error) => return Err(error),
        };
        Self::recover_locked(&path)
    }

    fn recover_locked(path: &Path) -> Result<Self> {
        let temporary = path.with_extension("tmp");
        if memory_snapshot_exists(&temporary)? {
            let pending = Self::load_existing(temporary)?;
            fs::rename(path.with_extension("tmp"), path)?;
            sync_parent_directory(path)?;
            return Ok(Self {
                path: path.to_path_buf(),
                records: pending.records,
            });
        }
        if memory_snapshot_exists(path)? {
            return Self::load_existing(path.to_path_buf());
        }
        Ok(Self {
            path: path.to_path_buf(),
            records: BTreeMap::new(),
        })
    }

    fn load_existing(path: PathBuf) -> Result<Self> {
        let bytes = read_memory_snapshot(&path)?;
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
        Self::open(path)
    }

    fn check_consent(
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<()> {
        grant.validate()?;
        if !grant.allows(resource_id)
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
        consent_registry: &ConsentRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        value: Value,
        now: u64,
    ) -> Result<String> {
        consent_registry.with_active_grant(grant, now, || {
            Self::check_consent(registry, grant, resource_id, now)?;
            let _lock = acquire_file_lock(&self.path, "persistent memory")?;
            let mut next_records = Self::recover_locked(&self.path)?.records;
            let value_digest = digest(&value)?;
            let record = MemoryRecord {
                tenant_id: grant.tenant_id.clone(),
                resource_id: resource_id.into(),
                grant_id: grant.grant_id.clone(),
                value,
                value_digest: value_digest.clone(),
            };
            next_records.insert(
                (record.tenant_id.clone(), record.resource_id.clone()),
                record,
            );
            self.save_records(&next_records)?;
            self.records = next_records;
            Ok(value_digest)
        })
    }

    pub fn retrieve(
        &self,
        registry: &SpecialistRegistry,
        consent_registry: &ConsentRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<Value> {
        consent_registry.with_active_grant(grant, now, || {
            Self::check_consent(registry, grant, resource_id, now)?;
            let _lock = acquire_file_lock(&self.path, "persistent memory")?;
            let current = Self::recover_locked(&self.path)?;
            let record = current
                .records
                .get(&(grant.tenant_id.clone(), resource_id.into()))
                .ok_or_else(|| Error::Invalid("resource not found".into()))?;
            if record.grant_id != grant.grant_id {
                return Err(Error::Rejected("memory grant binding mismatch".into()));
            }
            validate_record(record)?;
            Ok(record.value.clone())
        })
    }

    pub fn delete(
        &mut self,
        registry: &SpecialistRegistry,
        consent_registry: &ConsentRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<bool> {
        consent_registry.with_active_grant(grant, now, || {
            Self::check_consent(registry, grant, resource_id, now)?;
            let _lock = acquire_file_lock(&self.path, "persistent memory")?;
            let mut current = Self::recover_locked(&self.path)?.records;
            let key = (grant.tenant_id.clone(), resource_id.into());
            let Some(record) = current.get(&key) else {
                self.records = current;
                return Ok(false);
            };
            if record.grant_id != grant.grant_id {
                return Err(Error::Rejected("memory grant binding mismatch".into()));
            }
            current.remove(&key);
            self.save_records(&current)?;
            self.records = current;
            Ok(true)
        })
    }

    /// Returns the number of records in this handle's last loaded view.
    /// External writes are visible after `save`, `open`, or a mutation.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether this handle's last loaded view has no records.
    /// External writes are visible after `save`, `open`, or a mutation.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Persists the latest snapshot and refreshes this handle under the
    /// per-file writer lock. Mutations are durable when returned.
    pub fn save(&mut self) -> Result<()> {
        let _lock = acquire_file_lock(&self.path, "persistent memory")?;
        let current = Self::recover_locked(&self.path)?.records;
        self.save_records(&current)?;
        self.records = current;
        Ok(())
    }

    fn save_records(&self, records: &BTreeMap<(String, String), MemoryRecord>) -> Result<()> {
        for record in records.values() {
            validate_record(record)?;
        }
        let document = MemoryDocument {
            version: FORMAT_VERSION,
            records: records.values().cloned().collect(),
        };
        save_atomic_snapshot_locked(&self.path, &canonical_bytes(&document)?)
    }
}

fn memory_snapshot_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_memory_snapshot(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::Persistence(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "memory snapshot is not a regular file",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Persistence(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "memory snapshot is not owner-only",
            )));
        }
    }
    Ok(fs::read(path)?)
}
