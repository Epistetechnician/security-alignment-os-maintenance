//! Digest-only specialist routing records bound to consent and identity.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! Routing is a caller-selected local contract. It never receives raw prompt
//! content, classifies a request, loads a model, or invokes a specialist.

use crate::specialist::{ConsentGrant, SpecialistRegistry};
use crate::{digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub specialist_id: String,
    pub grant_id: String,
    pub input_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl RoutingRequest {
    pub fn new(
        request_id: String,
        tenant_id: String,
        specialist_id: String,
        grant_id: String,
        input_digest: String,
        created_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        let request = Self {
            request_id,
            tenant_id,
            specialist_id,
            grant_id,
            input_digest,
            created_at,
            expires_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.request_id)
            || !valid_text(&self.tenant_id)
            || !valid_text(&self.specialist_id)
            || !valid_digest(&self.grant_id)
            || !valid_digest(&self.input_digest)
            || self.expires_at <= self.created_at
        {
            return Err(Error::Invalid("invalid routing request".into()));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }

    fn active(&self, now: u64) -> bool {
        self.validate().is_ok() && self.created_at <= now && now < self.expires_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingDecision {
    pub request_digest: String,
    pub input_digest: String,
    pub tenant_id: String,
    pub specialist_id: String,
    pub specialist_digest: String,
    pub grant_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl RoutingDecision {
    pub fn route(
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        request: &RoutingRequest,
        now: u64,
    ) -> Result<Self> {
        request.validate()?;
        grant.validate()?;
        if !request.active(now)
            || !grant.active(now)
            || request.tenant_id != grant.tenant_id
            || request.specialist_id != grant.specialist_id
            || request.grant_id != grant.grant_id
        {
            return Err(Error::Rejected("routing consent binding is invalid".into()));
        }
        let identity = registry
            .resolve(&request.specialist_id, now)
            .ok_or_else(|| Error::Quarantined("specialist identity is unavailable".into()))?;
        let decision = Self {
            request_digest: request.digest()?,
            input_digest: request.input_digest.clone(),
            tenant_id: request.tenant_id.clone(),
            specialist_id: request.specialist_id.clone(),
            specialist_digest: identity.identity_digest()?,
            grant_id: grant.grant_id.clone(),
            issued_at: now,
            expires_at: request.expires_at.min(grant.expires_at),
        };
        decision.validate(registry, grant, request, now)?;
        Ok(decision)
    }

    pub fn validate(
        &self,
        registry: &SpecialistRegistry,
        grant: &ConsentGrant,
        request: &RoutingRequest,
        now: u64,
    ) -> Result<()> {
        request.validate()?;
        grant.validate()?;
        let identity = registry
            .resolve(&self.specialist_id, now)
            .ok_or_else(|| Error::Rejected("specialist identity is unavailable".into()))?;
        if !request.active(now)
            || !grant.active(now)
            || self.issued_at > now
            || self.issued_at < request.created_at
            || self.issued_at < grant.issued_at
            || now >= self.expires_at
            || self.expires_at > request.expires_at
            || self.expires_at > grant.expires_at
            || self.request_digest != request.digest()?
            || self.input_digest != request.input_digest
            || self.tenant_id != request.tenant_id
            || self.specialist_id != request.specialist_id
            || self.specialist_digest != identity.identity_digest()?
            || self.grant_id != grant.grant_id
            || request.tenant_id != grant.tenant_id
            || request.specialist_id != grant.specialist_id
            || request.grant_id != grant.grant_id
        {
            return Err(Error::Rejected("routing decision binding mismatch".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::specialist::SpecialistIdentity;
    use std::collections::BTreeSet;

    fn identity() -> SpecialistIdentity {
        SpecialistIdentity {
            specialist_id: "specialist".into(),
            version: "v1".into(),
            code_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            issued_at: 0,
        }
    }

    fn setup() -> (SpecialistRegistry, ConsentGrant, RoutingRequest) {
        let mut registry = SpecialistRegistry::default();
        registry.register(identity()).expect("identity");
        let grant = ConsentGrant::new(
            "tenant".into(),
            "specialist".into(),
            BTreeSet::from(["thread".into()]),
            0,
            100,
        )
        .expect("grant");
        let request = RoutingRequest::new(
            "request".into(),
            "tenant".into(),
            "specialist".into(),
            grant.grant_id.clone(),
            "c".repeat(64),
            10,
            90,
        )
        .expect("request");
        (registry, grant, request)
    }

    #[test]
    fn routing_binds_consent_identity_and_input_digest() {
        let (registry, grant, request) = setup();
        let decision = RoutingDecision::route(&registry, &grant, &request, 20).expect("route");
        decision
            .validate(&registry, &grant, &request, 20)
            .expect("validate");
        assert_eq!(decision.input_digest, request.input_digest);
        assert_eq!(decision.expires_at, 90);
    }

    #[test]
    fn routing_rejects_tampered_request_and_decision() {
        let (registry, grant, request) = setup();
        let mut changed = request.clone();
        changed.input_digest = "d".repeat(64);
        let decision = RoutingDecision::route(&registry, &grant, &request, 20).expect("route");
        assert!(decision.validate(&registry, &grant, &changed, 20).is_err());
        assert!(RoutingDecision::route(&registry, &grant, &changed, 20).is_ok());
        let mut tampered = decision;
        tampered.specialist_digest = "e".repeat(64);
        assert!(tampered.validate(&registry, &grant, &request, 20).is_err());
    }

    #[test]
    fn routing_rejects_expired_or_revoked_consent() {
        let (mut registry, grant, request) = setup();
        assert!(RoutingDecision::route(&registry, &grant, &request, 90).is_err());
        registry.revoke("specialist").expect("revoke");
        assert!(RoutingDecision::route(&registry, &grant, &request, 20).is_err());
    }

    #[test]
    fn routing_rejects_decision_issued_before_request_or_consent() {
        let (registry, grant, request) = setup();
        let mut decision = RoutingDecision::route(&registry, &grant, &request, 20).expect("route");
        decision.issued_at = 0;
        assert!(decision.validate(&registry, &grant, &request, 20).is_err());

        let mut decision = RoutingDecision::route(&registry, &grant, &request, 20).expect("route");
        decision.issued_at = 5;
        assert!(decision.validate(&registry, &grant, &request, 20).is_err());
    }
}
