//! Typed external-execution boundary that remains fail-closed locally.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! These records describe the controls a future executor would have to prove.
//! `ExecutionGate` never starts a process, opens a socket, brokers a secret, or
//! contacts a provider. The foundation disposition for every valid request is
//! `Blocked`.

use crate::{valid_digest, Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SandboxAttestation {
    pub attestation_id: String,
    pub executor_digest: String,
    pub egress_denied: bool,
    pub secret_broker: bool,
    pub independent_kill_path: bool,
    pub memory_bytes: u64,
    pub cpu_ms: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl SandboxAttestation {
    pub fn validate(&self, now: u64) -> Result<()> {
        if self.attestation_id.trim().is_empty()
            || !valid_digest(&self.executor_digest)
            || !self.egress_denied
            || !self.secret_broker
            || !self.independent_kill_path
            || self.memory_bytes == 0
            || self.cpu_ms == 0
            || self.expires_at <= self.issued_at
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(Error::Rejected(
                "sandbox attestation is incomplete or expired".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalExecutionRequest {
    pub request_id: String,
    pub program_digest: String,
    pub input_digest: String,
    pub output_schema_digest: String,
    pub proof_system: String,
    pub privacy_requirement: String,
    pub requested_at: u64,
    pub deadline: u64,
    pub max_price: u64,
}

impl ExternalExecutionRequest {
    pub fn validate(&self, now: u64) -> Result<()> {
        if self.request_id.trim().is_empty()
            || !valid_digest(&self.program_digest)
            || !valid_digest(&self.input_digest)
            || !valid_digest(&self.output_schema_digest)
            || self.proof_system.trim().is_empty()
            || self.privacy_requirement.trim().is_empty()
            || self.deadline <= self.requested_at
            || now < self.requested_at
            || now >= self.deadline
        {
            return Err(Error::Rejected(
                "external execution request is incomplete or expired".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GateDisposition {
    Blocked,
    Authorized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateDecision {
    pub disposition: GateDisposition,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionGate {
    external_authorization_enabled: bool,
}

impl ExecutionGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn authorize(
        &self,
        attestation: &SandboxAttestation,
        request: &ExternalExecutionRequest,
        now: u64,
    ) -> Result<GateDecision> {
        attestation.validate(now)?;
        request.validate(now)?;
        if self.external_authorization_enabled {
            return Err(Error::Rejected(
                "external authorization is not available in foundation slice".into(),
            ));
        }
        Ok(GateDecision {
            disposition: GateDisposition::Blocked,
            reason: "external execution is closed in foundation slice".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation() -> SandboxAttestation {
        SandboxAttestation {
            attestation_id: "attestation".into(),
            executor_digest: "a".repeat(64),
            egress_denied: true,
            secret_broker: true,
            independent_kill_path: true,
            memory_bytes: 1,
            cpu_ms: 1,
            issued_at: 0,
            expires_at: 100,
        }
    }

    fn request() -> ExternalExecutionRequest {
        ExternalExecutionRequest {
            request_id: "request".into(),
            program_digest: "b".repeat(64),
            input_digest: "c".repeat(64),
            output_schema_digest: "d".repeat(64),
            proof_system: "fixed-local-receipt".into(),
            privacy_requirement: "none".into(),
            requested_at: 0,
            deadline: 100,
            max_price: 0,
        }
    }

    #[test]
    fn valid_external_request_is_still_blocked() {
        let decision = ExecutionGate::new()
            .authorize(&attestation(), &request(), 10)
            .unwrap();
        assert_eq!(decision.disposition, GateDisposition::Blocked);
    }

    #[test]
    fn every_missing_sandbox_control_fails_closed() {
        for mutate in [
            |value: &mut SandboxAttestation| value.egress_denied = false,
            |value: &mut SandboxAttestation| value.secret_broker = false,
            |value: &mut SandboxAttestation| value.independent_kill_path = false,
        ] {
            let mut value = attestation();
            mutate(&mut value);
            assert!(value.validate(10).is_err());
        }
    }

    #[test]
    fn expired_attestation_and_request_are_rejected() {
        let mut value = attestation();
        value.expires_at = 10;
        assert!(ExecutionGate::new()
            .authorize(&value, &request(), 10)
            .is_err());
        let mut value = request();
        value.deadline = 10;
        assert!(ExecutionGate::new()
            .authorize(&attestation(), &value, 10)
            .is_err());
    }
}
