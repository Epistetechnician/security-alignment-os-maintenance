//! Local coordinator seam connecting evidence, admission, execution and observation.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The coordinator returns digests and dispositions only. Observation values
//! are caller-supplied assertions; this module does not inspect a process,
//! model, provider, network, or host security boundary.

use crate::{digest, DecisionKind, EvidenceRegistry, Kernel, Proposal, Result, Runtime};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Disposition {
    Quarantined,
    Rejected,
    Completed,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Observation {
    pub at: u64,
    pub healthy: bool,
    pub telemetry_present: bool,
    pub kill_requested: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowResult {
    pub disposition: Disposition,
    pub subject_digest: String,
    pub decision_digest: Option<String>,
    pub observation_digest: String,
}

pub fn run(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    evidence: &EvidenceRegistry,
    evidence_id: &str,
    proposal: &Proposal,
    observation: Observation,
) -> Result<WorkflowResult> {
    let subject_digest = proposal.digest()?;
    let observation_digest = digest(&observation)?;
    if !evidence.is_valid(evidence_id, observation.at, &subject_digest) {
        return Ok(WorkflowResult {
            disposition: Disposition::Quarantined,
            subject_digest,
            decision_digest: None,
            observation_digest,
        });
    }
    let decision = kernel.admit(proposal, observation.at)?;
    if decision.kind != DecisionKind::Accepted {
        return Ok(WorkflowResult {
            disposition: Disposition::Rejected,
            subject_digest,
            decision_digest: Some(decision.decision_digest),
            observation_digest,
        });
    }
    runtime.execute(kernel, proposal, &decision, observation.at)?;
    if observation.kill_requested || !observation.healthy || !observation.telemetry_present {
        let rolled_back = runtime.rollback("unhealthy observation");
        runtime.freeze("unhealthy observation");
        return Ok(WorkflowResult {
            disposition: if rolled_back {
                Disposition::RolledBack
            } else {
                Disposition::Rejected
            },
            subject_digest,
            decision_digest: Some(decision.decision_digest),
            observation_digest,
        });
    }
    Ok(WorkflowResult {
        disposition: Disposition::Completed,
        subject_digest,
        decision_digest: Some(decision.decision_digest),
        observation_digest,
    })
}
