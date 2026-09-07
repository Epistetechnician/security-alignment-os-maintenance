//! Typed external-adapter contracts.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! These records make the missing executor boundary explicit. They validate
//! bindings but never launch a process, open a socket, broker a secret, or
//! assert that an external adapter enforced the requested controls.

use crate::{valid_digest, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SandboxProfile {
    pub profile_id: String,
    pub executor_digest: String,
    pub egress_denied: bool,
    pub secret_broker_required: bool,
    pub independent_kill_path: bool,
    pub memory_bytes: u64,
    pub cpu_ms: u64,
}

impl SandboxProfile {
    pub fn validate(&self) -> Result<()> {
        if self.profile_id.is_empty()
            || !valid_digest(&self.executor_digest)
            || !self.egress_denied
            || !self.secret_broker_required
            || !self.independent_kill_path
            || self.memory_bytes == 0
            || self.cpu_ms == 0
        {
            return Err(Error::Invalid(
                "sandbox profile does not satisfy the fail-closed boundary".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ToolInvocation {
    pub invocation_id: String,
    pub tool_id: String,
    pub manifest_digest: String,
    pub capability_token_id: String,
    pub input_digest: String,
    pub consent_grant_id: String,
    pub created_at: u64,
}

impl ToolInvocation {
    pub fn validate(&self) -> Result<()> {
        if self.invocation_id.is_empty()
            || self.tool_id.is_empty()
            || self.capability_token_id.is_empty()
            || self.consent_grant_id.is_empty()
            || !valid_digest(&self.manifest_digest)
            || !valid_digest(&self.input_digest)
        {
            return Err(Error::Invalid(
                "tool invocation binding is incomplete".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdapterPlan {
    pub sandbox: SandboxProfile,
    pub invocation: ToolInvocation,
    pub external_execution_authorized: bool,
}

impl AdapterPlan {
    pub fn validate(&self) -> Result<()> {
        self.sandbox.validate()?;
        self.invocation.validate()?;
        if self.external_execution_authorized {
            return Err(Error::Rejected(
                "foundation slice cannot authorize external execution".into(),
            ));
        }
        Ok(())
    }
}
