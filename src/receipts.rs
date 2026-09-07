//! Signed capability receipts for the local control-plane boundary.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! A receipt authenticates a previously accepted local decision. It does not
//! authenticate a host, prove that execution happened, or authorize a
//! provider. Verification is intentionally caller-owned and in-memory.

use crate::{
    canonical_bytes, digest, valid_digest, Action, Capability, Decision, DecisionKind, Error,
    Policy, Proposal, Result, STATE_SLICE,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

const RECEIPT_VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;
const KEY_LEN: usize = 32;
const MAX_TEXT_LEN: usize = 256;
const VERIFIER_FORMAT_VERSION: u8 = 1;

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_LEN && !value.chars().any(char::is_control)
}

fn valid_key_id(value: &str) -> bool {
    valid_text(value)
}

fn validate_capability(capability: &Capability) -> Result<()> {
    if !valid_digest(&capability.token_id)
        || !valid_digest(&capability.intent_digest)
        || !valid_text(&capability.agent_id)
        || !valid_text(&capability.scope)
        || capability.issued_at >= capability.expires_at
    {
        return Err(Error::Invalid("capability fields are malformed".into()));
    }
    Ok(())
}

fn expected_decision_digest(
    proposal: &Proposal,
    decision: &Decision,
    policy_digest: &str,
    capability: &Capability,
) -> Result<String> {
    let candidate_digest = proposal.digest()?;
    digest(&(
        proposal.candidate_id.clone(),
        decision.kind,
        decision.reason.clone(),
        candidate_digest,
        policy_digest.to_owned(),
        capability.clone(),
    ))
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityReceipt {
    /// Digest of the complete proposal bytes.
    pub proposal_digest: String,
    /// Candidate digest from the accepted kernel decision.
    pub candidate_digest: String,
    /// Digest of the exact policy used for admission.
    pub policy_digest: String,
    /// Digest of the complete capability issued by the kernel.
    pub capability_digest: String,
    /// Caller or tenant subject to which this receipt is delegated.
    pub subject: String,
    /// Agent identity bound by the accepted proposal and capability.
    pub agent_id: String,
    pub action: Action,
    pub scope: String,
    pub issuer_key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Ed25519 signature over the canonical receipt payload, excluding this field.
    pub signature: Vec<u8>,
    /// Digest of the signed, non-signature receipt identity.
    pub receipt_id: String,
}

impl fmt::Debug for CapabilityReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityReceipt")
            .field("proposal_digest", &self.proposal_digest)
            .field("candidate_digest", &self.candidate_digest)
            .field("policy_digest", &self.policy_digest)
            .field("capability_digest", &self.capability_digest)
            .field("subject", &self.subject)
            .field("agent_id", &self.agent_id)
            .field("action", &self.action)
            .field("scope", &self.scope)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("signature", &"<redacted>")
            .field("receipt_id", &self.receipt_id)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize)]
struct ReceiptIdentityPayload<'a> {
    version: u8,
    state_slice: &'static str,
    proposal_digest: &'a str,
    candidate_digest: &'a str,
    policy_digest: &'a str,
    capability_digest: &'a str,
    subject: &'a str,
    agent_id: &'a str,
    action: Action,
    scope: &'a str,
    issuer_key_id: &'a str,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ReceiptSigningPayload<'a> {
    version: u8,
    state_slice: &'static str,
    proposal_digest: &'a str,
    candidate_digest: &'a str,
    policy_digest: &'a str,
    capability_digest: &'a str,
    subject: &'a str,
    agent_id: &'a str,
    action: Action,
    scope: &'a str,
    issuer_key_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    receipt_id: &'a str,
}

impl CapabilityReceipt {
    fn identity_payload(&self) -> ReceiptIdentityPayload<'_> {
        ReceiptIdentityPayload {
            version: RECEIPT_VERSION,
            state_slice: STATE_SLICE,
            proposal_digest: &self.proposal_digest,
            candidate_digest: &self.candidate_digest,
            policy_digest: &self.policy_digest,
            capability_digest: &self.capability_digest,
            subject: &self.subject,
            agent_id: &self.agent_id,
            action: self.action,
            scope: &self.scope,
            issuer_key_id: &self.issuer_key_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    fn signing_payload(&self) -> ReceiptSigningPayload<'_> {
        ReceiptSigningPayload {
            version: RECEIPT_VERSION,
            state_slice: STATE_SLICE,
            proposal_digest: &self.proposal_digest,
            candidate_digest: &self.candidate_digest,
            policy_digest: &self.policy_digest,
            capability_digest: &self.capability_digest,
            subject: &self.subject,
            agent_id: &self.agent_id,
            action: self.action,
            scope: &self.scope,
            issuer_key_id: &self.issuer_key_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            receipt_id: &self.receipt_id,
        }
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&self.signing_payload())
    }

    fn expected_id(&self) -> Result<String> {
        digest(&self.identity_payload())
    }

    fn validate_shape(&self) -> Result<()> {
        if !valid_digest(&self.proposal_digest)
            || !valid_digest(&self.candidate_digest)
            || !valid_digest(&self.policy_digest)
            || !valid_digest(&self.capability_digest)
            || !valid_digest(&self.receipt_id)
        {
            return Err(Error::Invalid(
                "receipt digest fields must be lowercase SHA-256 digests".into(),
            ));
        }
        if !valid_text(&self.subject)
            || !valid_text(&self.agent_id)
            || !valid_text(&self.scope)
            || !valid_key_id(&self.issuer_key_id)
        {
            return Err(Error::Invalid(
                "receipt identity fields are malformed".into(),
            ));
        }
        if self.issued_at >= self.expires_at {
            return Err(Error::Invalid("receipt issuance window is invalid".into()));
        }
        if self.signature.len() != SIGNATURE_LEN {
            return Err(Error::Invalid("receipt signature length is invalid".into()));
        }
        if self.receipt_id != self.expected_id()? {
            return Err(Error::Invalid("receipt identity digest mismatch".into()));
        }
        Ok(())
    }

    /// Validates the non-signature shape and deterministic identity binding.
    /// Signature authenticity additionally requires `ReceiptVerifier::verify`.
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        self.validate_shape().is_ok() && self.issued_at <= now && now < self.expires_at
    }
}

/// Ed25519 receipt issuer. The private key is deliberately not exposed or
/// included in `Debug`, serialization, or receipt fields.
pub struct ReceiptSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl ReceiptSigner {
    /// Constructs an issuer from an Ed25519 seed. The seed is caller-owned and
    /// never logged or copied into a receipt.
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; KEY_LEN]) -> Result<Self> {
        let key_id = key_id.into();
        if !valid_key_id(&key_id) {
            return Err(Error::Invalid("issuer key ID is malformed".into()));
        }
        Ok(Self {
            key_id,
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key_bytes(&self) -> [u8; KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Issues a receipt using the capability's complete validity window.
    pub fn issue(
        &self,
        subject: &str,
        proposal: &Proposal,
        decision: &Decision,
        policy: &Policy,
    ) -> Result<CapabilityReceipt> {
        let capability = decision
            .capability
            .as_ref()
            .ok_or_else(|| Error::Rejected("accepted decision lacks capability".into()))?;
        self.issue_at(
            subject,
            proposal,
            decision,
            policy,
            capability.issued_at,
            capability.expires_at,
        )
    }

    /// Issues a receipt within the capability's existing window. This is
    /// useful when a caller needs a receipt that expires before the token.
    pub fn issue_at(
        &self,
        subject: &str,
        proposal: &Proposal,
        decision: &Decision,
        policy: &Policy,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<CapabilityReceipt> {
        if !valid_text(subject) {
            return Err(Error::Invalid("receipt subject is malformed".into()));
        }
        if decision.kind != DecisionKind::Accepted {
            return Err(Error::Rejected(
                "only accepted decisions can receive a receipt".into(),
            ));
        }
        let capability = decision
            .capability
            .as_ref()
            .ok_or_else(|| Error::Rejected("accepted decision lacks capability".into()))?;
        validate_capability(capability)?;
        let proposal_digest = proposal.digest()?;
        let policy_digest = digest(policy)?;
        let capability_digest = digest(capability)?;
        let expected_intent_digest = digest(&(
            &proposal.agent_id,
            &proposal.intent,
            &proposal.action,
            &proposal.scope,
            &proposal.nonce,
        ))?;
        let expected_token_id = digest(&(
            proposal_digest.clone(),
            capability.issued_at,
            policy_digest.clone(),
        ))?;
        if decision.candidate_digest != proposal_digest
            || decision.candidate_id != proposal.candidate_id
            || decision.policy_digest != policy_digest
            || decision.decision_digest
                != expected_decision_digest(proposal, decision, &policy_digest, capability)?
            || capability.agent_id != proposal.agent_id
            || capability.action != proposal.action
            || capability.scope != proposal.scope
            || capability.intent_digest != expected_intent_digest
            || capability.token_id != expected_token_id
            || capability.budget != proposal.resource_cost
        {
            return Err(Error::Rejected(
                "decision, proposal, policy, or capability binding failed".into(),
            ));
        }
        if issued_at < capability.issued_at
            || expires_at > capability.expires_at
            || issued_at >= expires_at
        {
            return Err(Error::Rejected(
                "receipt window exceeds capability validity".into(),
            ));
        }
        let mut receipt = CapabilityReceipt {
            proposal_digest,
            candidate_digest: decision.candidate_digest.clone(),
            policy_digest,
            capability_digest,
            subject: subject.into(),
            agent_id: capability.agent_id.clone(),
            action: capability.action,
            scope: capability.scope.clone(),
            issuer_key_id: self.key_id.clone(),
            issued_at,
            expires_at,
            signature: Vec::new(),
            receipt_id: String::new(),
        };
        receipt.receipt_id = receipt.expected_id()?;
        receipt.signature = self
            .signing_key
            .sign(&receipt.signing_bytes()?)
            .to_bytes()
            .to_vec();
        receipt.validate_shape()?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct VerifierDocument {
    version: u8,
    trusted_keys: BTreeMap<String, Vec<u8>>,
    verified: BTreeSet<String>,
}

/// Local verifier with an explicit trusted-key map and replay set. Trust and
/// replay state can be persisted by the caller, but the file remains
/// unauthenticated caller-owned storage.
pub struct ReceiptVerifier {
    trusted_keys: BTreeMap<String, VerifyingKey>,
    verified: BTreeSet<String>,
}

impl Default for ReceiptVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptVerifier {
    pub fn new() -> Self {
        Self {
            trusted_keys: BTreeMap::new(),
            verified: BTreeSet::new(),
        }
    }

    pub fn with_key(key_id: impl Into<String>, public_key: [u8; KEY_LEN]) -> Result<Self> {
        let mut verifier = Self::new();
        verifier.register_key(key_id, public_key)?;
        Ok(verifier)
    }

    pub fn register_key(
        &mut self,
        key_id: impl Into<String>,
        public_key: [u8; KEY_LEN],
    ) -> Result<()> {
        let key_id = key_id.into();
        if !valid_key_id(&key_id) {
            return Err(Error::Invalid("issuer key ID is malformed".into()));
        }
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| Error::Invalid("issuer public key is malformed".into()))?;
        if self.trusted_keys.contains_key(&key_id) {
            return Err(Error::Rejected("issuer key ID already registered".into()));
        }
        self.trusted_keys.insert(key_id, key);
        self.validate()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        for (key_id, key) in &self.trusted_keys {
            if !valid_key_id(key_id) || VerifyingKey::from_bytes(&key.to_bytes()).is_err() {
                return Err(Error::Invalid(
                    "receipt verifier key registry is malformed".into(),
                ));
            }
        }
        if self
            .verified
            .iter()
            .any(|receipt_id| !valid_digest(receipt_id))
        {
            return Err(Error::Invalid(
                "receipt verifier replay set is malformed".into(),
            ));
        }
        Ok(())
    }

    fn document(&self) -> VerifierDocument {
        VerifierDocument {
            version: VERIFIER_FORMAT_VERSION,
            trusted_keys: self
                .trusted_keys
                .iter()
                .map(|(key_id, key)| (key_id.clone(), key.to_bytes().to_vec()))
                .collect(),
            verified: self.verified.clone(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(&self.document())?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let document: VerifierDocument = serde_json::from_slice(&bytes)?;
        if document.version != VERIFIER_FORMAT_VERSION || canonical_bytes(&document)? != bytes {
            return Err(Error::Journal(
                "receipt verifier bytes are not canonical JSON".into(),
            ));
        }
        let mut verifier = Self::new();
        for (key_id, bytes) in document.trusted_keys {
            let public_key: [u8; KEY_LEN] = bytes
                .try_into()
                .map_err(|_| Error::Invalid("issuer public key is malformed".into()))?;
            verifier.register_key(key_id, public_key)?;
        }
        verifier.verified = document.verified;
        verifier.validate()?;
        Ok(verifier)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(verifier) => Ok(verifier),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let verifier = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(verifier)
            }
            Err(error) => Err(error),
        }
    }

    pub fn verified_count(&self) -> usize {
        self.verified.len()
    }

    pub fn is_verified(&self, receipt_id: &str) -> bool {
        self.verified.contains(receipt_id)
    }

    /// Verifies signature, freshness, exact decision binding, and delegation
    /// identity. A receipt enters the replay set only after every check passes.
    pub fn verify(
        &mut self,
        receipt: &CapabilityReceipt,
        subject: &str,
        proposal: &Proposal,
        decision: &Decision,
        policy: &Policy,
        now: u64,
    ) -> Result<()> {
        receipt.validate_shape()?;
        if !valid_text(subject) || receipt.subject != subject {
            return Err(Error::Rejected(
                "receipt subject delegation mismatch".into(),
            ));
        }
        if !receipt.is_valid_at(now) {
            return Err(Error::Rejected(
                "receipt is outside its validity window".into(),
            ));
        }
        if self.verified.contains(&receipt.receipt_id) {
            return Err(Error::Rejected("receipt replayed".into()));
        }
        let verifying_key = self
            .trusted_keys
            .get(&receipt.issuer_key_id)
            .ok_or_else(|| Error::Rejected("issuer key is not trusted".into()))?;
        let signature_bytes: [u8; SIGNATURE_LEN] = receipt
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("receipt signature length is invalid".into()))?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&receipt.signing_bytes()?, &signature)
            .map_err(|_| Error::Rejected("receipt signature verification failed".into()))?;

        let capability = decision
            .capability
            .as_ref()
            .ok_or_else(|| Error::Rejected("accepted decision lacks capability".into()))?;
        validate_capability(capability)?;
        let proposal_digest = proposal.digest()?;
        let policy_digest = digest(policy)?;
        let capability_digest = digest(capability)?;
        let expected_intent_digest = digest(&(
            &proposal.agent_id,
            &proposal.intent,
            &proposal.action,
            &proposal.scope,
            &proposal.nonce,
        ))?;
        let expected_token_id = digest(&(
            proposal_digest.clone(),
            capability.issued_at,
            policy_digest.clone(),
        ))?;
        if decision.kind != DecisionKind::Accepted
            || decision.decision_digest
                != expected_decision_digest(proposal, decision, &policy_digest, capability)?
            || decision.candidate_id != proposal.candidate_id
            || receipt.proposal_digest != proposal_digest
            || receipt.candidate_digest != decision.candidate_digest
            || decision.candidate_digest != proposal_digest
            || receipt.policy_digest != policy_digest
            || receipt.policy_digest != decision.policy_digest
            || receipt.capability_digest != capability_digest
            || receipt.agent_id != proposal.agent_id
            || receipt.agent_id != capability.agent_id
            || receipt.action != proposal.action
            || receipt.action != capability.action
            || receipt.scope != proposal.scope
            || receipt.scope != capability.scope
            || capability.intent_digest != expected_intent_digest
            || capability.token_id != expected_token_id
            || capability.budget != proposal.resource_cost
            || receipt.issued_at < capability.issued_at
            || receipt.expires_at > capability.expires_at
        {
            return Err(Error::Rejected(
                "receipt proposal, decision, policy, or capability delegation mismatch".into(),
            ));
        }
        self.verified.insert(receipt.receipt_id.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Claim, Kernel};

    fn fixture() -> (Proposal, Policy, Decision) {
        let policy = Policy::default();
        let proposal = Proposal {
            candidate_id: "candidate-1".into(),
            agent_id: "agent-1".into(),
            intent: "write a bounded local value".into(),
            action: Action::Write,
            scope: "public".into(),
            payload: [
                ("key".into(), serde_json::Value::String("public:k".into())),
                ("value".into(), serde_json::Value::String("v".into())),
            ]
            .into_iter()
            .collect(),
            resource_cost: [
                ("cpu_ms".into(), 1),
                ("bytes".into(), 1),
                ("spend".into(), 0),
            ]
            .into_iter()
            .collect(),
            source_digest: "a".repeat(64),
            claims: vec![Claim {
                guarantees: vec!["PolicyCompliance".into()],
                assumptions: Vec::new(),
                excludes: Vec::new(),
                maturity: 1,
                trust_roots: vec!["local".into()],
                valid_until: 1_000,
                provenance_digest: "b".repeat(64),
            }],
            nonce: 1,
            expires_at: 1_000,
            requests_direct_authority: false,
        };
        let mut kernel = Kernel::new(policy.clone()).expect("policy");
        let decision = kernel.admit(&proposal, 100).expect("admission");
        (proposal, policy, decision)
    }

    fn signer() -> ReceiptSigner {
        ReceiptSigner::from_seed("issuer-1", [7; KEY_LEN]).expect("signer")
    }

    #[test]
    fn signed_receipt_verifies_once_and_replay_is_rejected() {
        let (proposal, policy, decision) = fixture();
        let signer = signer();
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        let receipt = signer
            .issue("tenant-1", &proposal, &decision, &policy)
            .expect("receipt");
        verifier
            .verify(&receipt, "tenant-1", &proposal, &decision, &policy, 100)
            .expect("verification");
        crate::checker::validate_capability_receipt(
            &receipt,
            "tenant-1",
            &proposal,
            &decision,
            &policy,
            signer.verifying_key_bytes(),
            100,
        )
        .expect("independent verification");
        assert_eq!(verifier.verified_count(), 1);
        assert!(verifier
            .verify(&receipt, "tenant-1", &proposal, &decision, &policy, 100)
            .is_err());
    }

    #[test]
    fn expired_receipt_is_rejected_after_valid_signature() {
        let (proposal, policy, decision) = fixture();
        let signer = signer();
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        let receipt = signer
            .issue_at("tenant-1", &proposal, &decision, &policy, 120, 130)
            .expect("receipt");
        assert!(verifier
            .verify(&receipt, "tenant-1", &proposal, &decision, &policy, 130)
            .is_err());
        assert_eq!(verifier.verified_count(), 0);
    }

    #[test]
    fn subject_and_capability_delegation_mismatches_fail_closed() {
        let (proposal, policy, decision) = fixture();
        let signer = signer();
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        let receipt = signer
            .issue("tenant-1", &proposal, &decision, &policy)
            .expect("receipt");
        assert!(verifier
            .verify(&receipt, "tenant-2", &proposal, &decision, &policy, 100)
            .is_err());
        let mut delegated = decision.clone();
        let capability = delegated.capability.as_mut().expect("capability");
        capability.action = Action::Read;
        assert!(verifier
            .verify(&receipt, "tenant-1", &proposal, &delegated, &policy, 100)
            .is_err());
        let mut wrong_agent = decision.clone();
        wrong_agent
            .capability
            .as_mut()
            .expect("capability")
            .agent_id = "agent-2".into();
        assert!(verifier
            .verify(&receipt, "tenant-1", &proposal, &wrong_agent, &policy, 100)
            .is_err());
        let mut wrong_scope = decision.clone();
        wrong_scope.capability.as_mut().expect("capability").scope = "sandbox".into();
        assert!(verifier
            .verify(&receipt, "tenant-1", &proposal, &wrong_scope, &policy, 100)
            .is_err());
        let mut wrong_candidate = decision.clone();
        wrong_candidate.candidate_id = "candidate-2".into();
        assert!(signer
            .issue("tenant-1", &proposal, &wrong_candidate, &policy)
            .is_err());
        assert!(verifier
            .verify(
                &receipt,
                "tenant-1",
                &proposal,
                &wrong_candidate,
                &policy,
                100
            )
            .is_err());
        assert_eq!(verifier.verified_count(), 0);
    }

    #[test]
    fn malformed_signature_and_key_inputs_are_rejected() {
        let (proposal, policy, decision) = fixture();
        let signer = signer();
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        let mut receipt = signer
            .issue("tenant-1", &proposal, &decision, &policy)
            .expect("receipt");
        receipt.signature.pop();
        assert!(verifier
            .verify(&receipt, "tenant-1", &proposal, &decision, &policy, 100)
            .is_err());
        assert!(ReceiptSigner::from_seed("", [7; KEY_LEN]).is_err());
        assert!(verifier
            .register_key(signer.key_id(), signer.verifying_key_bytes())
            .is_err());
    }

    #[test]
    fn verifier_snapshot_preserves_trust_and_replay_state() {
        let (proposal, policy, decision) = fixture();
        let signer = signer();
        let receipt = signer
            .issue("tenant-1", &proposal, &decision, &policy)
            .expect("receipt");
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        verifier
            .verify(&receipt, "tenant-1", &proposal, &decision, &policy, 100)
            .expect("verification");

        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("receipt-verifier.json");
        verifier.save(&path).expect("save");
        let mut restored = ReceiptVerifier::load(&path).expect("load");
        assert_eq!(restored.verified_count(), 1);
        assert!(restored
            .verify(&receipt, "tenant-1", &proposal, &decision, &policy, 100)
            .is_err());

        let canonical = std::fs::read(&path).expect("canonical");
        let mut tampered = canonical.clone();
        let tamper_index = tampered.len() - 2;
        tampered[tamper_index] = b' ';
        std::fs::write(&path, tampered).expect("tamper");
        assert!(ReceiptVerifier::load(&path).is_err());
        std::fs::write(path.with_extension("tmp"), canonical).expect("temporary");
        std::fs::remove_file(&path).expect("remove primary");
        let recovered = ReceiptVerifier::recover(&path).expect("recover");
        assert_eq!(recovered.verified_count(), 1);
    }
}
