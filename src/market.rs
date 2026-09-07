//! One fixed local compute receipt class; no provider or settlement execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};

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
        if job_id.is_empty()
            || requester.is_empty()
            || inputs.is_empty()
            || inputs.len() > 1024
            || deadline == 0
        {
            return Err(Error::Invalid("invalid fixed compute job".into()));
        }
        checked_sum(&inputs)?;
        Ok(Self {
            job_id,
            requester,
            inputs,
            deadline,
            max_price,
            program_digest,
        })
    }
    pub fn digest(&self) -> Result<String> {
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

fn checked_sum(inputs: &[u64]) -> Result<u64> {
    inputs.iter().try_fold(0u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| Error::Rejected("fixed sum overflow".into()))
    })
}

pub fn execute_local(job: &SumJob, now: u64) -> Result<SumReceipt> {
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

impl ReceiptVerifier {
    pub fn verify(&mut self, job: &SumJob, receipt: &SumReceipt, now: u64) -> Result<bool> {
        let valid = !receipt.provider.is_empty()
            && receipt.provider != job.requester
            && receipt.completed_at <= now
            && now < job.deadline
            && receipt.job_digest == job.digest()?
            && receipt.program_digest == job.program_digest
            && receipt.input_digest == digest(&job.inputs)?
            && receipt.succeeded
            && receipt.output == checked_sum(&job.inputs)?
            && receipt.price <= job.max_price
            && valid_digest(&receipt.job_digest);
        if !valid {
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
        if now >= job.deadline
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
