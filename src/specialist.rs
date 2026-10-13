//! Rust-native specialist identity, consent, tool manifest, and telemetry contracts.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::persistence::{
    acquire_file_lock, read_regular_snapshot, recover_atomic_snapshot, save_atomic_snapshot,
    sync_parent_directory,
};
use crate::{canonical_bytes, digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecialistIdentity {
    pub specialist_id: String,
    pub version: String,
    pub code_digest: String,
    pub policy_digest: String,
    pub issued_at: u64,
}

impl SpecialistIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.specialist_id.is_empty()
            || self.version.is_empty()
            || self
                .specialist_id
                .chars()
                .any(|character| character.is_control())
            || self.version.chars().any(|character| character.is_control())
            || !valid_digest(&self.code_digest)
            || !valid_digest(&self.policy_digest)
        {
            return Err(Error::Invalid("invalid specialist identity".into()));
        }
        Ok(())
    }
    pub fn identity_digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecialistRegistry {
    identities: BTreeMap<String, SpecialistIdentity>,
    revoked: BTreeSet<String>,
}

impl SpecialistRegistry {
    pub fn validate(&self) -> Result<()> {
        if self
            .revoked
            .iter()
            .any(|specialist_id| !self.identities.contains_key(specialist_id))
        {
            return Err(Error::Invalid(
                "revoked specialist is not registered".into(),
            ));
        }
        for (specialist_id, identity) in &self.identities {
            if specialist_id != &identity.specialist_id {
                return Err(Error::Invalid("specialist registry key mismatch".into()));
            }
            identity.validate()?;
        }
        Ok(())
    }

    pub fn register(&mut self, identity: SpecialistIdentity) -> Result<()> {
        identity.validate()?;
        if self.revoked.contains(&identity.specialist_id) {
            return Err(Error::Rejected("specialist is revoked".into()));
        }
        if self
            .identities
            .get(&identity.specialist_id)
            .is_some_and(|old| old != &identity)
        {
            return Err(Error::Rejected("specialist identity drift".into()));
        }
        self.identities
            .insert(identity.specialist_id.clone(), identity);
        self.validate()?;
        Ok(())
    }
    pub fn revoke(&mut self, specialist_id: &str) -> Result<()> {
        if !self.identities.contains_key(specialist_id) {
            return Err(Error::Invalid("unknown specialist".into()));
        }
        if !self.revoked.insert(specialist_id.into()) {
            return Err(Error::Rejected("specialist is already revoked".into()));
        }
        Ok(())
    }
    pub fn resolve(&self, specialist_id: &str, now: u64) -> Option<&SpecialistIdentity> {
        self.identities
            .get(specialist_id)
            .filter(|identity| !self.revoked.contains(specialist_id) && identity.issued_at <= now)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        save_atomic_snapshot(path, &canonical_bytes(self)?, "specialist registry")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_snapshot(path)?;
        let registry: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&registry)? != bytes {
            return Err(Error::Journal(
                "specialist registry bytes are not canonical JSON".into(),
            ));
        }
        registry.validate()?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        recover_atomic_snapshot(path, "specialist registry", Self::load)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsentGrant {
    pub tenant_id: String,
    pub specialist_id: String,
    pub resource_ids: BTreeSet<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub grant_id: String,
}

impl ConsentGrant {
    pub fn new(
        tenant_id: String,
        specialist_id: String,
        resource_ids: BTreeSet<String>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        if tenant_id.is_empty()
            || specialist_id.is_empty()
            || resource_ids.is_empty()
            || expires_at <= issued_at
        {
            return Err(Error::Invalid("invalid consent grant".into()));
        }
        let grant_id = digest(&(
            tenant_id.clone(),
            specialist_id.clone(),
            resource_ids.clone(),
            issued_at,
            expires_at,
        ))?;
        let grant = Self {
            tenant_id,
            specialist_id,
            resource_ids,
            issued_at,
            expires_at,
            grant_id,
        };
        grant.validate()?;
        Ok(grant)
    }
    pub fn validate(&self) -> Result<()> {
        if self.tenant_id.is_empty()
            || self.specialist_id.is_empty()
            || self.resource_ids.is_empty()
            || self.resource_ids.iter().any(String::is_empty)
            || self.expires_at <= self.issued_at
            || !valid_digest(&self.grant_id)
        {
            return Err(Error::Invalid("invalid consent grant".into()));
        }
        let expected = digest(&(
            self.tenant_id.clone(),
            self.specialist_id.clone(),
            self.resource_ids.clone(),
            self.issued_at,
            self.expires_at,
        ))?;
        if expected != self.grant_id {
            return Err(Error::Rejected("consent grant digest mismatch".into()));
        }
        Ok(())
    }
    pub fn active(&self, now: u64) -> bool {
        self.validate().is_ok() && self.issued_at <= now && now < self.expires_at
    }
    pub fn allows(&self, resource_id: &str) -> bool {
        self.resource_ids.contains(resource_id) || self.resource_ids.contains("*")
    }
}

const CONSENT_FORMAT_VERSION: u8 = 1;

fn write_consent_snapshot(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_parent_directory(path)
}

fn read_consent_snapshot(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::Journal(
            "consent registry snapshot is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Journal(
                "consent registry snapshot is not owner-only".into(),
            ));
        }
    }
    Ok(fs::read(path)?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ConsentDocument {
    version: u8,
    grants: Vec<ConsentGrant>,
    revoked_grants: BTreeSet<String>,
}

/// Caller-owned consent registry shared by routing, retrieval, and persistent
/// memory. Revocation is terminal for a grant ID; a new issuance has a new ID.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsentRegistry {
    grants: BTreeMap<String, ConsentGrant>,
    revoked_grants: BTreeSet<String>,
    persistence_path: Option<PathBuf>,
}

impl ConsentRegistry {
    pub fn validate(&self) -> Result<()> {
        if self
            .revoked_grants
            .iter()
            .any(|grant_id| !valid_digest(grant_id) || self.grants.contains_key(grant_id))
        {
            return Err(Error::Invalid("invalid consent revocation ledger".into()));
        }
        for (grant_id, grant) in &self.grants {
            if grant_id != &grant.grant_id {
                return Err(Error::Invalid("consent registry key mismatch".into()));
            }
            grant.validate()?;
        }
        Ok(())
    }

    fn grant_in_memory(&mut self, grant: ConsentGrant) -> Result<()> {
        grant.validate()?;
        if self.revoked_grants.contains(&grant.grant_id) {
            return Err(Error::Rejected("consent grant was revoked".into()));
        }
        if self
            .grants
            .get(&grant.grant_id)
            .is_some_and(|registered| registered != &grant)
        {
            return Err(Error::Rejected("consent grant identity collision".into()));
        }
        self.grants.insert(grant.grant_id.clone(), grant);
        self.validate()
    }

    fn revoke_in_memory(&mut self, grant_id: &str) -> Result<()> {
        if self.revoked_grants.contains(grant_id) {
            return Err(Error::Rejected("consent grant is already revoked".into()));
        }
        if self.grants.remove(grant_id).is_none() {
            return Err(Error::Invalid("unknown consent grant".into()));
        }
        self.revoked_grants.insert(grant_id.into());
        self.validate()
    }

    /// Opens the current owner-controlled snapshot and persists every later
    /// grant or revocation under a single-writer file lock.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let _lock = acquire_file_lock(&path, "consent registry")?;
        let mut registry = match Self::recover_locked(&path) {
            Ok(registry) => registry,
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let registry = Self::default();
                registry.write_snapshot(&path)?;
                registry
            }
            Err(error) => return Err(error),
        };
        registry.persistence_path = Some(path);
        Ok(registry)
    }

    /// Applies a grant update. Opened registries reload the latest snapshot
    /// under the writer lock, so a stale handle cannot erase a revocation.
    pub fn grant(&mut self, grant: ConsentGrant) -> Result<()> {
        self.update_persistent(|registry| registry.grant_in_memory(grant.clone()))
    }

    /// Persists a terminal revocation before returning for an opened registry.
    pub fn revoke(&mut self, grant_id: &str) -> Result<()> {
        self.update_persistent(|registry| registry.revoke_in_memory(grant_id))
    }

    fn update_persistent(&mut self, update: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let Some(path) = self.persistence_path.clone() else {
            return update(self);
        };
        let _lock = acquire_file_lock(&path, "consent registry")?;
        let mut current = Self::recover_locked(&path)?;
        update(&mut current)?;
        current.write_snapshot(&path)?;
        self.grants = current.grants;
        self.revoked_grants = current.revoked_grants;
        Ok(())
    }

    fn contains_active_grant(&self, grant: &ConsentGrant, now: u64) -> bool {
        self.validate().is_ok()
            && grant.validate().is_ok()
            && self.grants.get(&grant.grant_id) == Some(grant)
            && grant.active(now)
    }

    /// Returns true only while this exact grant is registered and active.
    pub fn has_active_grant(&self, grant: &ConsentGrant, now: u64) -> bool {
        if let Some(path) = &self.persistence_path {
            let Ok(_lock) = acquire_file_lock(path, "consent registry") else {
                return false;
            };
            return Self::recover_locked(path)
                .is_ok_and(|current| current.contains_active_grant(grant, now));
        }
        self.contains_active_grant(grant, now)
    }

    /// Holds the persistent registry lock through the caller's consent-gated
    /// effect. The closure must not re-enter this registry.
    pub fn with_active_grant<T>(
        &self,
        grant: &ConsentGrant,
        now: u64,
        effect: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if let Some(path) = &self.persistence_path {
            let _lock = acquire_file_lock(path, "consent registry")?;
            let current = Self::recover_locked(path)?;
            if !current.contains_active_grant(grant, now) {
                return Err(Error::Rejected("consent grant is not active".into()));
            }
            return effect();
        }
        if !self.contains_active_grant(grant, now) {
            return Err(Error::Rejected("consent grant is not active".into()));
        }
        effect()
    }

    fn document(&self) -> ConsentDocument {
        ConsentDocument {
            version: CONSENT_FORMAT_VERSION,
            grants: self.grants.values().cloned().collect(),
            revoked_grants: self.revoked_grants.clone(),
        }
    }

    fn write_snapshot(&self, path: &Path) -> Result<()> {
        self.validate()?;
        write_consent_snapshot(path, &canonical_bytes(&self.document())?)
    }

    /// Saves a one-time initial snapshot from an in-memory registry. Use
    /// `open` for persistent state that will receive later updates.
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.persistence_path.is_some() {
            return Err(Error::Rejected(
                "opened consent registries persist through grant and revoke".into(),
            ));
        }
        let _lock = acquire_file_lock(path, "consent registry")?;
        let temporary = path.with_extension("tmp");
        if consent_snapshot_exists(path)? || consent_snapshot_exists(&temporary)? {
            return Err(Error::Rejected(
                "initial consent snapshot already exists; open it for updates".into(),
            ));
        }
        self.write_snapshot(path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_consent_snapshot(path)?;
        let document: ConsentDocument = serde_json::from_slice(&bytes)?;
        if document.version != CONSENT_FORMAT_VERSION || canonical_bytes(&document)? != bytes {
            return Err(Error::Journal(
                "consent registry bytes are noncanonical or unsupported".into(),
            ));
        }
        let mut registry = Self {
            grants: BTreeMap::new(),
            revoked_grants: document.revoked_grants,
            persistence_path: None,
        };
        for grant in document.grants {
            grant.validate()?;
            if registry
                .grants
                .insert(grant.grant_id.clone(), grant)
                .is_some()
            {
                return Err(Error::Journal("duplicate consent grant identity".into()));
            }
        }
        registry
            .validate()
            .map_err(|error| Error::Journal(format!("invalid consent registry: {error}")))?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        let _lock = acquire_file_lock(path, "consent registry")?;
        let mut registry = Self::recover_locked(path)?;
        registry.persistence_path = Some(path.to_path_buf());
        Ok(registry)
    }

    fn recover_locked(path: &Path) -> Result<Self> {
        let temporary = path.with_extension("tmp");
        if consent_snapshot_exists(&temporary)? {
            let pending = Self::load(&temporary)?;
            fs::rename(&temporary, path)?;
            sync_parent_directory(path)?;
            return Ok(pending);
        }
        Self::load(path)
    }
}

fn consent_snapshot_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Debug, Default)]
pub struct TenantRetrieval {
    records: BTreeMap<(String, String), Value>,
}

impl TenantRetrieval {
    pub fn put(&mut self, tenant_id: String, resource_id: String, value: Value) -> Result<()> {
        if tenant_id.is_empty() || resource_id.is_empty() {
            return Err(Error::Invalid("tenant and resource are required".into()));
        }
        self.records.insert((tenant_id, resource_id), value);
        Ok(())
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
            if !grant.allows(resource_id) || registry.resolve(&grant.specialist_id, now).is_none() {
                return Err(Error::Rejected("consent or specialist is invalid".into()));
            }
            self.records
                .get(&(grant.tenant_id.clone(), resource_id.into()))
                .cloned()
                .ok_or_else(|| Error::Invalid("resource not found".into()))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolManifest {
    pub tool_id: String,
    pub version: String,
    pub schema: Value,
    pub implementation_digest: String,
}

impl ToolManifest {
    pub fn validate(&self) -> Result<()> {
        if self.tool_id.is_empty()
            || self.version.is_empty()
            || !valid_digest(&self.implementation_digest)
        {
            return Err(Error::Invalid("invalid tool manifest".into()));
        }
        Ok(())
    }
    pub fn identity_digest(&self) -> Result<String> {
        self.validate()?;
        digest(&(
            self.tool_id.clone(),
            self.version.clone(),
            self.schema.clone(),
            self.implementation_digest.clone(),
        ))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolRegistry {
    manifests: BTreeMap<String, ToolManifest>,
    frozen_digest: Option<String>,
    revoked: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TelemetryEvent {
    Proposal,
    Decision,
    Execution,
    Freeze,
    Kill,
    Rollback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TelemetryOutcome {
    Accepted,
    Rejected,
    Quarantined,
    Completed,
    Failed,
    Frozen,
    Killed,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedTelemetry {
    pub event: TelemetryEvent,
    pub outcome: TelemetryOutcome,
    pub identity_digest: String,
    pub fields: Value,
}

impl RedactedTelemetry {
    pub fn new(
        event: TelemetryEvent,
        outcome: TelemetryOutcome,
        identity_digest: String,
        fields: Value,
    ) -> Result<Self> {
        if !valid_digest(&identity_digest) {
            return Err(Error::Invalid(
                "telemetry identity digest is invalid".into(),
            ));
        }
        Ok(Self {
            event,
            outcome,
            identity_digest,
            fields: redact(fields),
        })
    }
}

fn redact(value: Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .filter(|(key, _)| !sensitive_key(key))
                .map(|(key, value)| (key, redact(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact).collect()),
        other => other,
    }
}

fn sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "credential",
        "token",
        "secret",
        "password",
        "prompt",
        "payload",
        "content",
    ]
    .iter()
    .any(|fragment| normalized.contains(fragment))
}

impl ToolRegistry {
    pub fn register(&mut self, manifest: ToolManifest) -> Result<()> {
        manifest.validate()?;
        if self.frozen_digest.is_some() {
            return Err(Error::Rejected("tool list is frozen".into()));
        }
        if self.revoked.contains(&manifest.tool_id) {
            return Err(Error::Rejected("tool is revoked".into()));
        }
        if self
            .manifests
            .get(&manifest.tool_id)
            .is_some_and(|old| old != &manifest)
        {
            return Err(Error::Rejected("tool manifest drift".into()));
        }
        self.manifests.insert(manifest.tool_id.clone(), manifest);
        Ok(())
    }

    fn manifest_list_digest(&self) -> Result<String> {
        let ids: Vec<String> = self
            .manifests
            .values()
            .map(ToolManifest::identity_digest)
            .collect::<Result<_>>()?;
        digest(&(ids, &self.revoked))
    }

    pub fn freeze(&mut self) -> Result<String> {
        if self.frozen_digest.is_some() {
            return Err(Error::Rejected("tool list is already frozen".into()));
        }
        let list = self.manifest_list_digest()?;
        self.frozen_digest = Some(list.clone());
        Ok(list)
    }

    pub fn revoke(&mut self, tool_id: &str) -> Result<()> {
        if !self.manifests.contains_key(tool_id) {
            return Err(Error::Invalid("unknown tool".into()));
        }
        if !self.revoked.insert(tool_id.into()) {
            return Err(Error::Rejected("tool is already revoked".into()));
        }
        Ok(())
    }

    pub fn require_invocable(&self, tool_id: &str, manifest_digest: &str) -> Result<&ToolManifest> {
        if !valid_digest(manifest_digest) {
            return Err(Error::Invalid("tool manifest digest is malformed".into()));
        }
        if self.revoked.contains(tool_id) {
            return Err(Error::Rejected("tool is revoked".into()));
        }
        let manifest = self
            .manifests
            .get(tool_id)
            .ok_or_else(|| Error::Quarantined("tool is unavailable".into()))?;
        if manifest.identity_digest()? != manifest_digest {
            return Err(Error::Rejected("tool manifest digest mismatch".into()));
        }
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self
            .revoked
            .iter()
            .any(|tool_id| !self.manifests.contains_key(tool_id))
        {
            return Err(Error::Invalid("revoked tool is not registered".into()));
        }
        for (tool_id, manifest) in &self.manifests {
            if tool_id != &manifest.tool_id {
                return Err(Error::Invalid("tool registry key mismatch".into()));
            }
            manifest.validate()?;
        }
        if let Some(frozen_digest) = &self.frozen_digest {
            if !valid_digest(frozen_digest) {
                return Err(Error::Invalid("frozen tool digest is malformed".into()));
            }
        }
        Ok(())
    }

    pub fn check_drift(&self) -> bool {
        self.frozen_digest
            .as_ref()
            .is_some_and(|expected| self.manifest_list_digest().ok().as_ref() == Some(expected))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        save_atomic_snapshot(path, &canonical_bytes(self)?, "tool registry")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_snapshot(path)?;
        let registry: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&registry)? != bytes {
            return Err(Error::Journal(
                "tool registry bytes are not canonical JSON".into(),
            ));
        }
        registry.validate()?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        recover_atomic_snapshot(path, "tool registry", Self::load)
    }
}

#[cfg(test)]
mod tool_registry_tests {
    use super::*;

    fn manifest() -> ToolManifest {
        ToolManifest {
            tool_id: "local-tool".into(),
            version: "1.0.0".into(),
            schema: serde_json::json!({"type": "object"}),
            implementation_digest: "a".repeat(64),
        }
    }

    #[test]
    fn frozen_tool_identity_supports_terminal_revocation() {
        let item = manifest();
        let item_digest = item.identity_digest().expect("manifest digest");
        let mut registry = ToolRegistry::default();
        registry.register(item.clone()).expect("register");
        assert!(registry
            .require_invocable("local-tool", &item_digest)
            .is_ok());
        registry.freeze().expect("freeze");
        assert!(registry.check_drift());
        assert!(registry.freeze().is_err());
        registry.revoke("local-tool").expect("revoke");
        assert!(!registry.check_drift());
        assert!(registry
            .require_invocable("local-tool", &item_digest)
            .is_err());
        assert!(registry.register(item).is_err());
        assert!(registry.revoke("local-tool").is_err());
    }

    #[test]
    fn tool_registry_snapshot_is_canonical_and_rejects_drifted_bytes() {
        let mut registry = ToolRegistry::default();
        registry.register(manifest()).expect("register");
        registry.freeze().expect("freeze");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("tools.json");
        registry.save(&path).expect("save");
        assert_eq!(ToolRegistry::load(&path).expect("load"), registry);
        let mut bytes = std::fs::read(&path).expect("read");
        let tamper_index = bytes.len() - 2;
        bytes[tamper_index] = b' ';
        std::fs::write(&path, bytes).expect("tamper");
        assert!(ToolRegistry::load(&path).is_err());
        std::fs::write(
            path.with_extension("tmp"),
            crate::canonical_bytes(&registry).expect("canonical"),
        )
        .expect("temporary snapshot");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(ToolRegistry::recover(&path).expect("recover"), registry);
    }
}

#[cfg(test)]
mod specialist_registry_tests {
    use super::*;

    fn identity() -> SpecialistIdentity {
        SpecialistIdentity {
            specialist_id: "specialist-1".into(),
            version: "1.0.0".into(),
            code_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            issued_at: 10,
        }
    }

    #[test]
    fn identity_registry_is_immutable_and_revocation_is_terminal() {
        let item = identity();
        let mut registry = SpecialistRegistry::default();
        registry.register(item.clone()).expect("register");
        assert_eq!(registry.resolve("specialist-1", 10), Some(&item));
        registry.revoke("specialist-1").expect("revoke");
        assert!(registry.resolve("specialist-1", 10).is_none());
        assert!(registry.revoke("specialist-1").is_err());
        assert!(registry.register(item).is_err());
    }

    #[test]
    fn specialist_registry_snapshot_is_canonical_and_recoverable() {
        let mut registry = SpecialistRegistry::default();
        registry.register(identity()).expect("register");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("specialists.json");
        registry.save(&path).expect("save");
        assert_eq!(SpecialistRegistry::load(&path).expect("load"), registry);
        let mut bytes = std::fs::read(&path).expect("read");
        let tamper_index = bytes.len() - 2;
        bytes[tamper_index] = b' ';
        std::fs::write(&path, bytes).expect("tamper");
        assert!(SpecialistRegistry::load(&path).is_err());
        std::fs::write(
            path.with_extension("tmp"),
            crate::canonical_bytes(&registry).expect("canonical"),
        )
        .expect("temporary snapshot");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(
            SpecialistRegistry::recover(&path).expect("recover"),
            registry
        );
    }
}
