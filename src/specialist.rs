//! Rust-native specialist identity, consent, tool manifest, and telemetry contracts.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{canonical_bytes, digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

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

#[derive(Clone, Debug, Default)]
pub struct SpecialistRegistry {
    identities: BTreeMap<String, SpecialistIdentity>,
    revoked: BTreeSet<String>,
}

impl SpecialistRegistry {
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
        Ok(())
    }
    pub fn revoke(&mut self, specialist_id: &str) -> Result<()> {
        if self.identities.contains_key(specialist_id) {
            self.revoked.insert(specialist_id.into());
            Ok(())
        } else {
            Err(Error::Invalid("unknown specialist".into()))
        }
    }
    pub fn resolve(&self, specialist_id: &str, now: u64) -> Option<&SpecialistIdentity> {
        self.identities
            .get(specialist_id)
            .filter(|identity| !self.revoked.contains(specialist_id) && identity.issued_at <= now)
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

#[derive(Clone, Debug, Default)]
pub struct TenantRetrieval {
    records: BTreeMap<(String, String), Value>,
    grants: BTreeMap<String, ConsentGrant>,
}

impl TenantRetrieval {
    pub fn put(&mut self, tenant_id: String, resource_id: String, value: Value) -> Result<()> {
        if tenant_id.is_empty() || resource_id.is_empty() {
            return Err(Error::Invalid("tenant and resource are required".into()));
        }
        self.records.insert((tenant_id, resource_id), value);
        Ok(())
    }
    pub fn grant(&mut self, grant: ConsentGrant) -> Result<()> {
        grant.validate()?;
        self.grants.insert(grant.grant_id.clone(), grant);
        Ok(())
    }
    pub fn revoke(&mut self, grant_id: &str) {
        self.grants.remove(grant_id);
    }
    pub fn retrieve(
        &self,
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        resource_id: &str,
        now: u64,
    ) -> Result<Value> {
        if grant.validate().is_err()
            || self.grants.get(&grant.grant_id) != Some(grant)
            || !grant.active(now)
            || !grant.allows(resource_id)
            || registry.resolve(&grant.specialist_id, now).is_none()
        {
            return Err(Error::Rejected("consent or specialist is invalid".into()));
        }
        self.records
            .get(&(grant.tenant_id.clone(), resource_id.into()))
            .cloned()
            .ok_or_else(|| Error::Invalid("resource not found".into()))
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
                "tool registry bytes are not canonical JSON".into(),
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
