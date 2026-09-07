//! Rust-native specialist identity, consent, tool manifest, and telemetry contracts.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Clone, Debug, Default)]
pub struct ToolRegistry {
    manifests: BTreeMap<String, ToolManifest>,
    frozen_digest: Option<String>,
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
    pub fn freeze(&mut self) -> Result<String> {
        let ids: Vec<String> = self
            .manifests
            .values()
            .map(ToolManifest::identity_digest)
            .collect::<Result<_>>()?;
        let list = digest(&ids)?;
        self.frozen_digest = Some(list.clone());
        Ok(list)
    }
    pub fn check_drift(&self) -> bool {
        self.frozen_digest.as_ref().is_some_and(|expected| {
            let ids: Vec<String> = self
                .manifests
                .values()
                .map(ToolManifest::identity_digest)
                .collect::<Result<_>>()
                .unwrap_or_default();
            digest(&ids).ok().as_ref() == Some(expected)
        })
    }
}
