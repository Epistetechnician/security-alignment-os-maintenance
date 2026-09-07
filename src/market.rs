//! One fixed local compute receipt class; no provider or settlement execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const VERIFIER_FORMAT_VERSION: u8 = 1;

fn output_schema_digest() -> Result<String> {
    digest(&("fixed-u64-output", 1u8))
}

fn runtime_digest() -> Result<String> {
    digest(&("fixed-local-sum-runtime", 1u8))
}

fn result_digest(job: &SumJob, output: u64) -> Result<String> {
    digest(&(&job.program_digest, &job.inputs, output))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SumJob {
    pub job_id: String,
    pub requester: String,
    pub inputs: Vec<u64>,
    pub input_commitment: String,
    pub deadline: u64,
    pub max_price: u64,
    pub program_digest: String,
    pub output_schema_digest: String,
    pub receipt_type: String,
    pub privacy_requirement: String,
}

impl SumJob {
    pub fn new(
        job_id: String,
        requester: String,
        inputs: Vec<u64>,
        deadline: u64,
        max_price: u64,
    ) -> Result<Self> {
        let program_digest = digest(&("fixed-integer-sum", 1u8))?;
        let input_commitment = digest(&inputs)?;
        let job = Self {
            job_id,
            requester,
            inputs,
            input_commitment,
            deadline,
            max_price,
            program_digest,
            output_schema_digest: output_schema_digest()?,
            receipt_type: "ordinary-receipt-v1".into(),
            privacy_requirement: "none".into(),
        };
        job.validate()?;
        Ok(job)
    }

    pub fn validate(&self) -> Result<()> {
        let expected_program_digest = digest(&("fixed-integer-sum", 1u8))?;
        let expected_output_schema_digest = output_schema_digest()?;
        if self.job_id.is_empty()
            || self.job_id.chars().any(|character| character.is_control())
            || self.requester.is_empty()
            || self
                .requester
                .chars()
                .any(|character| character.is_control())
            || self.inputs.is_empty()
            || self.inputs.len() > 1024
            || self.input_commitment != digest(&self.inputs)?
            || self.deadline == 0
            || self.program_digest != expected_program_digest
            || self.output_schema_digest != expected_output_schema_digest
            || self.receipt_type != "ordinary-receipt-v1"
            || self.privacy_requirement != "none"
        {
            return Err(Error::Invalid("invalid fixed compute job".into()));
        }
        checked_sum(&self.inputs)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SumReceipt {
    pub job_digest: String,
    pub offer_id: String,
    pub runtime_digest: String,
    pub program_digest: String,
    pub input_digest: String,
    pub output_schema_digest: String,
    pub receipt_type: String,
    pub privacy_requirement: String,
    pub result_digest: String,
    pub provider: String,
    pub output: u64,
    pub completed_at: u64,
    pub price: u64,
    pub succeeded: bool,
}

impl SumReceipt {
    pub fn validate(&self, job: &SumJob, now: u64) -> Result<()> {
        job.validate()?;
        if self.provider.is_empty()
            || self
                .provider
                .chars()
                .any(|character| character.is_control())
            || self.provider == job.requester
            || self.offer_id.is_empty()
            || self
                .offer_id
                .chars()
                .any(|character| character.is_control())
            || self.runtime_digest != runtime_digest()?
            || self.completed_at > now
            || now >= job.deadline
            || self.job_digest != job.digest()?
            || self.program_digest != job.program_digest
            || self.input_digest != digest(&job.inputs)?
            || self.input_digest != job.input_commitment
            || self.output_schema_digest != job.output_schema_digest
            || self.receipt_type != job.receipt_type
            || self.privacy_requirement != job.privacy_requirement
            || !self.succeeded
            || self.output != checked_sum(&job.inputs)?
            || self.result_digest != result_digest(job, self.output)?
            || self.price > job.max_price
            || !valid_digest(&self.job_digest)
            || !valid_digest(&self.program_digest)
            || !valid_digest(&self.input_digest)
        {
            return Err(Error::Rejected("fixed compute receipt is invalid".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SumOffer {
    pub job_digest: String,
    pub offer_id: String,
    pub provider: String,
    pub runtime_digest: String,
    pub result_digest: String,
    pub receipt_type: String,
    pub price: u64,
    pub submitted_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SettlementStatus {
    AuthorizationRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementProposal {
    pub job_digest: String,
    pub offer_id: String,
    pub receipt_digest: String,
    pub provider: String,
    pub price: u64,
    pub status: SettlementStatus,
}

impl SettlementProposal {
    pub fn validate(&self, job: &SumJob, receipt: &SumReceipt) -> Result<()> {
        job.validate()?;
        receipt.validate(job, receipt.completed_at)?;
        if self.job_digest != job.digest()?
            || self.offer_id != receipt.offer_id
            || self.receipt_digest != digest(receipt)?
            || self.provider != receipt.provider
            || self.price != receipt.price
            || self.status != SettlementStatus::AuthorizationRequired
        {
            return Err(Error::Rejected(
                "settlement proposal binding mismatch".into(),
            ));
        }
        Ok(())
    }
}

impl SumOffer {
    pub fn new(
        job: &SumJob,
        offer_id: String,
        provider: String,
        price: u64,
        submitted_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        job.validate()?;
        let output = checked_sum(&job.inputs)?;
        let offer = Self {
            job_digest: job.digest()?,
            offer_id,
            provider,
            runtime_digest: runtime_digest()?,
            result_digest: result_digest(job, output)?,
            receipt_type: job.receipt_type.clone(),
            price,
            submitted_at,
            expires_at,
        };
        offer.validate(job, submitted_at)?;
        Ok(offer)
    }

    pub fn validate(&self, job: &SumJob, now: u64) -> Result<()> {
        job.validate()?;
        if self.offer_id.is_empty()
            || self.job_digest != job.digest()?
            || self
                .offer_id
                .chars()
                .any(|character| character.is_control())
            || self.provider.is_empty()
            || self
                .provider
                .chars()
                .any(|character| character.is_control())
            || self.provider == job.requester
            || self.runtime_digest != runtime_digest()?
            || self.result_digest != result_digest(job, checked_sum(&job.inputs)?)?
            || self.receipt_type != job.receipt_type
            || self.price > job.max_price
            || self.submitted_at > now
            || self.expires_at <= self.submitted_at
            || self.expires_at > job.deadline
        {
            return Err(Error::Rejected("fixed compute offer is invalid".into()));
        }
        Ok(())
    }
}

pub fn select_offer<'a>(job: &SumJob, offers: &'a [SumOffer], now: u64) -> Result<&'a SumOffer> {
    let mut eligible = offers
        .iter()
        .filter(|offer| offer.validate(job, now).is_ok() && now < offer.expires_at)
        .collect::<Vec<_>>();
    eligible.sort_by(|left, right| {
        (left.price, &left.provider, &left.offer_id).cmp(&(
            right.price,
            &right.provider,
            &right.offer_id,
        ))
    });
    eligible
        .into_iter()
        .next()
        .ok_or_else(|| Error::Quarantined("no eligible fixed compute offer".into()))
}

fn checked_sum(inputs: &[u64]) -> Result<u64> {
    inputs.iter().try_fold(0u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| Error::Rejected("fixed sum overflow".into()))
    })
}

pub fn execute_local(job: &SumJob, now: u64) -> Result<SumReceipt> {
    job.validate()?;
    if now >= job.deadline {
        return Err(Error::Rejected("job expired".into()));
    }
    let output = checked_sum(&job.inputs)?;
    Ok(SumReceipt {
        job_digest: job.digest()?,
        offer_id: "local-direct-v1".into(),
        runtime_digest: runtime_digest()?,
        program_digest: job.program_digest.clone(),
        input_digest: digest(&job.inputs)?,
        output_schema_digest: job.output_schema_digest.clone(),
        receipt_type: job.receipt_type.clone(),
        privacy_requirement: job.privacy_requirement.clone(),
        result_digest: result_digest(job, output)?,
        provider: "local-sum".into(),
        output,
        completed_at: now,
        price: 0,
        succeeded: true,
    })
}

pub fn execute_local_with_offer(job: &SumJob, offer: &SumOffer, now: u64) -> Result<SumReceipt> {
    offer.validate(job, now)?;
    if now >= job.deadline || now >= offer.expires_at {
        return Err(Error::Rejected("fixed compute offer expired".into()));
    }
    let output = checked_sum(&job.inputs)?;
    let expected_result_digest = result_digest(job, output)?;
    if offer.result_digest != expected_result_digest {
        return Err(Error::Rejected("offer result commitment mismatched".into()));
    }
    Ok(SumReceipt {
        job_digest: job.digest()?,
        offer_id: offer.offer_id.clone(),
        runtime_digest: offer.runtime_digest.clone(),
        program_digest: job.program_digest.clone(),
        input_digest: digest(&job.inputs)?,
        output_schema_digest: job.output_schema_digest.clone(),
        receipt_type: job.receipt_type.clone(),
        privacy_requirement: job.privacy_requirement.clone(),
        result_digest: expected_result_digest,
        provider: offer.provider.clone(),
        output,
        completed_at: now,
        price: offer.price,
        succeeded: true,
    })
}

#[derive(Debug, Default)]
pub struct ReceiptVerifier {
    verified: std::collections::BTreeSet<String>,
    reserved: std::collections::BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct VerifierDocument {
    version: u8,
    verified: BTreeSet<String>,
    reserved: BTreeSet<String>,
}

impl ReceiptVerifier {
    pub fn validate(&self) -> Result<()> {
        if self
            .verified
            .iter()
            .chain(&self.reserved)
            .any(|value| !valid_digest(value))
        {
            return Err(Error::Invalid(
                "market verifier state contains malformed digest".into(),
            ));
        }
        Ok(())
    }

    fn document(&self) -> VerifierDocument {
        VerifierDocument {
            version: VERIFIER_FORMAT_VERSION,
            verified: self.verified.clone(),
            reserved: self.reserved.clone(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, crate::canonical_bytes(&self.document())?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let document: VerifierDocument = serde_json::from_slice(&bytes)?;
        if document.version != VERIFIER_FORMAT_VERSION
            || crate::canonical_bytes(&document)? != bytes
        {
            return Err(Error::Journal(
                "market verifier bytes are not canonical JSON".into(),
            ));
        }
        let verifier = Self {
            verified: document.verified,
            reserved: document.reserved,
        };
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

    pub fn verify(&mut self, job: &SumJob, receipt: &SumReceipt, now: u64) -> Result<bool> {
        if job.validate().is_err() || receipt.validate(job, now).is_err() {
            return Ok(false);
        }
        Ok(self.verified.insert(digest(receipt)?))
    }
    pub fn propose_settlement(
        &mut self,
        job: &SumJob,
        receipt: &SumReceipt,
        now: u64,
    ) -> Result<SettlementProposal> {
        if receipt.offer_id != "local-direct-v1" {
            return Err(Error::Rejected(
                "offer-backed settlement requires exact offer binding".into(),
            ));
        }
        self.propose_settlement_inner(job, receipt, now)
    }

    pub fn propose_settlement_for_offer(
        &mut self,
        job: &SumJob,
        offer: &SumOffer,
        receipt: &SumReceipt,
        now: u64,
    ) -> Result<SettlementProposal> {
        offer.validate(job, now)?;
        if receipt.offer_id != offer.offer_id
            || receipt.provider != offer.provider
            || receipt.price != offer.price
            || receipt.runtime_digest != offer.runtime_digest
        {
            return Err(Error::Rejected(
                "receipt does not bind the selected offer".into(),
            ));
        }
        self.propose_settlement_inner(job, receipt, now)
    }

    fn propose_settlement_inner(
        &mut self,
        job: &SumJob,
        receipt: &SumReceipt,
        now: u64,
    ) -> Result<SettlementProposal> {
        let receipt_digest = digest(receipt)?;
        if receipt.validate(job, now).is_err()
            || now >= job.deadline
            || !self.verified.contains(&receipt_digest)
            || !self.reserved.insert(job.digest()?)
        {
            return Err(Error::Rejected(
                "receipt is unverified, expired, or replayed".into(),
            ));
        }
        let proposal = SettlementProposal {
            job_digest: job.digest()?,
            offer_id: receipt.offer_id.clone(),
            receipt_digest,
            provider: receipt.provider.clone(),
            price: receipt.price,
            status: SettlementStatus::AuthorizationRequired,
        };
        proposal.validate(job, receipt)?;
        Ok(proposal)
    }
}
