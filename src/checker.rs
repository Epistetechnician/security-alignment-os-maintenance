//! Independent recomputation for the local public control-plane records.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! These checks deliberately reimplement the record equations instead of
//! calling producer `validate` methods. They provide local regression checks,
//! not authenticated independent acceptance or proof of an external executor.

use crate::audit::AuditJournal;
use crate::market::{SumJob, SumReceipt};
use crate::receipts::CapabilityReceipt;
use crate::{
    canonical_bytes, digest, valid_digest, Action, Decision, DecisionKind, Error, Policy, Proposal,
    ReplayJournal, Result, STATE_SLICE,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use std::collections::BTreeSet;

const RECEIPT_VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;

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

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

pub fn validate_replay(journal: &ReplayJournal) -> Result<()> {
    let mut previous = "0".repeat(64);
    let mut seen = BTreeSet::new();
    for (index, entry) in journal.entries.iter().enumerate() {
        if entry.sequence != index as u64
            || entry.previous_digest != previous
            || !valid_digest(&entry.candidate_digest)
            || !valid_digest(&entry.decision_digest)
            || !valid_digest(&entry.entry_digest)
            || !seen.insert(entry.candidate_digest.clone())
        {
            return Err(Error::Journal("independent replay check failed".into()));
        }
        let expected = digest(&(
            &entry.sequence,
            &entry.previous_digest,
            &entry.candidate_digest,
            &entry.decision_digest,
        ))?;
        if expected != entry.entry_digest {
            return Err(Error::Journal("independent replay digest mismatch".into()));
        }
        previous = entry.entry_digest.clone();
    }
    Ok(())
}

pub fn validate_audit(journal: &AuditJournal) -> Result<()> {
    let mut previous = "0".repeat(64);
    for (index, entry) in journal.entries.iter().enumerate() {
        if entry.sequence != index as u64
            || entry.previous_digest != previous
            || !valid_digest(&entry.previous_digest)
            || !valid_digest(&entry.entry_digest)
        {
            return Err(Error::Journal("independent audit check failed".into()));
        }
        let expected = digest(&(entry.sequence, &entry.previous_digest, &entry.metadata))?;
        if expected != entry.entry_digest {
            return Err(Error::Journal("independent audit digest mismatch".into()));
        }
        previous = entry.entry_digest.clone();
    }
    Ok(())
}

pub fn validate_receipt(job: &SumJob, receipt: &SumReceipt, now: u64) -> Result<()> {
    let output = job.inputs.iter().try_fold(0u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| Error::Rejected("independent receipt sum overflow".into()))
    })?;
    if receipt.provider.is_empty()
        || receipt.provider == job.requester
        || receipt.completed_at > now
        || now >= job.deadline
        || receipt.job_digest != digest(job)?
        || receipt.program_digest != job.program_digest
        || receipt.input_digest != digest(&job.inputs)?
        || !receipt.succeeded
        || receipt.output != output
        || receipt.price > job.max_price
        || !valid_digest(&receipt.job_digest)
    {
        return Err(Error::Rejected("independent receipt check failed".into()));
    }
    Ok(())
}

/// Independently validates a signed capability receipt.
///
/// This function intentionally duplicates the receipt equations instead of
/// calling `CapabilityReceipt::validate` or `ReceiptVerifier::verify`. It checks
/// the exact proposal/decision/policy/capability bindings, receipt identity,
/// validity window, and Ed25519 signature using the caller-provided public
/// key. The caller still owns trust in that key and any durable replay store.
pub fn validate_capability_receipt(
    receipt: &CapabilityReceipt,
    subject: &str,
    proposal: &Proposal,
    decision: &Decision,
    policy: &Policy,
    public_key: [u8; 32],
    now: u64,
) -> Result<()> {
    let capability = decision
        .capability
        .as_ref()
        .ok_or_else(|| Error::Rejected("accepted decision lacks capability".into()))?;
    let proposal_digest = proposal.digest()?;
    let policy_digest = digest(policy)?;
    let capability_digest = digest(capability)?;
    let expected_decision_digest = digest(&(
        proposal.candidate_id.clone(),
        decision.kind,
        decision.reason.clone(),
        proposal_digest.clone(),
        policy_digest.clone(),
        capability.clone(),
    ))?;
    if decision.kind != DecisionKind::Accepted
        || !valid_text(subject)
        || !valid_digest(&receipt.proposal_digest)
        || !valid_digest(&receipt.candidate_digest)
        || !valid_digest(&receipt.policy_digest)
        || !valid_digest(&receipt.capability_digest)
        || !valid_digest(&receipt.receipt_id)
        || !valid_text(&receipt.subject)
        || receipt.subject != subject
        || !valid_text(&receipt.agent_id)
        || !valid_text(&receipt.scope)
        || !valid_text(&receipt.issuer_key_id)
        || receipt.issued_at >= receipt.expires_at
        || receipt.issued_at < capability.issued_at
        || receipt.expires_at > capability.expires_at
        || receipt.issued_at > now
        || now >= receipt.expires_at
        || !valid_digest(&capability.token_id)
        || !valid_digest(&capability.intent_digest)
        || !valid_text(&capability.agent_id)
        || !valid_text(&capability.scope)
        || capability.issued_at >= capability.expires_at
        || decision.candidate_digest != proposal_digest
        || decision.policy_digest != policy_digest
        || decision.decision_digest != expected_decision_digest
        || receipt.proposal_digest != proposal_digest
        || receipt.candidate_digest != decision.candidate_digest
        || receipt.policy_digest != policy_digest
        || receipt.policy_digest != decision.policy_digest
        || receipt.capability_digest != capability_digest
        || receipt.agent_id != proposal.agent_id
        || receipt.agent_id != capability.agent_id
        || receipt.action != proposal.action
        || receipt.action != capability.action
        || receipt.scope != proposal.scope
        || receipt.scope != capability.scope
    {
        return Err(Error::Rejected(
            "independent capability receipt binding check failed".into(),
        ));
    }
    if receipt.signature.len() != SIGNATURE_LEN {
        return Err(Error::Rejected(
            "independent capability receipt signature length check failed".into(),
        ));
    }
    let expected_receipt_id = digest(&ReceiptIdentityPayload {
        version: RECEIPT_VERSION,
        state_slice: STATE_SLICE,
        proposal_digest: &receipt.proposal_digest,
        candidate_digest: &receipt.candidate_digest,
        policy_digest: &receipt.policy_digest,
        capability_digest: &receipt.capability_digest,
        subject: &receipt.subject,
        agent_id: &receipt.agent_id,
        action: receipt.action,
        scope: &receipt.scope,
        issuer_key_id: &receipt.issuer_key_id,
        issued_at: receipt.issued_at,
        expires_at: receipt.expires_at,
    })?;
    if receipt.receipt_id != expected_receipt_id {
        return Err(Error::Rejected(
            "independent capability receipt identity check failed".into(),
        ));
    }
    let signing_payload = ReceiptSigningPayload {
        version: RECEIPT_VERSION,
        state_slice: STATE_SLICE,
        proposal_digest: &receipt.proposal_digest,
        candidate_digest: &receipt.candidate_digest,
        policy_digest: &receipt.policy_digest,
        capability_digest: &receipt.capability_digest,
        subject: &receipt.subject,
        agent_id: &receipt.agent_id,
        action: receipt.action,
        scope: &receipt.scope,
        issuer_key_id: &receipt.issuer_key_id,
        issued_at: receipt.issued_at,
        expires_at: receipt.expires_at,
        receipt_id: &receipt.receipt_id,
    };
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::Rejected("independent capability public key invalid".into()))?;
    let signature_bytes: [u8; SIGNATURE_LEN] = receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Rejected("independent capability signature invalid".into()))?;
    key.verify(
        &canonical_bytes(&signing_payload)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| Error::Rejected("independent capability signature check failed".into()))
}
