//! Independent recomputation for the local public control-plane records.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! These checks deliberately reimplement the record equations instead of
//! calling producer `validate` methods. They provide local regression checks,
//! not authenticated independent acceptance or proof of an external executor.

use crate::audit::AuditJournal;
use crate::market::{SumJob, SumReceipt};
use crate::{digest, valid_digest, Error, ReplayJournal, Result};
use std::collections::BTreeSet;

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
