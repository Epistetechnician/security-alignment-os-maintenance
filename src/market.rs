//! One fixed local compute receipt class; no provider or settlement execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const VERIFIER_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SumJob {
    pub job_id: String,
    pub requester: String,
    pub inputs: Vec<u64>,
    pub deadline: u64,
    pub max_price: u64,
    pub program_digest: String,
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
        let job = Self {
            job_id,
            requester,
            inputs,
            deadline,
            max_price,
            program_digest,
        };
        job.validate()?;
        Ok(job)
    }

    pub fn validate(&self) -> Result<()> {
        let expected_program_digest = digest(&("fixed-integer-sum", 1u8))?;
        if self.job_id.is_empty()
            || self.job_id.chars().any(|character| character.is_control())
            || self.requester.is_empty()
            || self
                .requester
                .chars()
                .any(|character| character.is_control())
            || self.inputs.is_empty()
            || self.inputs.len() > 1024
            || self.deadline == 0
            || self.program_digest != expected_program_digest
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
    pub program_digest: String,
    pub input_digest: String,
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
            || self.completed_at > now
            || now >= job.deadline
            || self.job_digest != job.digest()?
            || self.program_digest != job.program_digest
            || self.input_digest != digest(&job.inputs)?
            || !self.succeeded
            || self.output != checked_sum(&job.inputs)?
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
        program_digest: job.program_digest.clone(),
        input_digest: digest(&job.inputs)?,
        provider: "local-sum".into(),
        output,
        completed_at: now,
        price: 0,
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
    ) -> Result<serde_json::Value> {
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
        Ok(
            serde_json::json!({"job_digest": job.digest()?, "receipt_digest": receipt_digest, "executed": false, "authorization_required": true}),
        )
    }
}
