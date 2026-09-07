//! Local coordinator seam connecting evidence, admission, execution and observation.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The coordinator returns digests and dispositions only. Observation values
//! are caller-supplied assertions; this module does not inspect a process,
//! model, provider, network, or host security boundary.

use crate::receipts::{CapabilityReceipt, ReceiptVerifier};
use crate::{
    artifacts::ArtifactRegistry, contract, digest, DecisionKind, EvidenceRegistry, Kernel,
    Proposal, Result, Runtime,
};
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

pub struct EvidenceBinding<'a> {
    pub evidence: &'a EvidenceRegistry,
    pub evidence_id: &'a str,
    pub artifacts: &'a ArtifactRegistry,
    pub artifact_id: &'a str,
}

pub struct ReceiptBinding<'a> {
    pub verifier: &'a mut ReceiptVerifier,
    pub receipt: &'a CapabilityReceipt,
    pub subject: &'a str,
}

fn observe_failure(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    kind: contract::FailureKind,
) -> Result<contract::BudgetDecision> {
    match kernel.observe_failure(kind) {
        Ok(decision) => {
            if decision == contract::BudgetDecision::FreezeRequired {
                runtime.freeze("failure budget exhausted");
            }
            Ok(decision)
        }
        Err(error) => {
            runtime.freeze("failure budget state invalid or exhausted");
            kernel.freeze_all()?;
            Err(error)
        }
    }
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
        observe_failure(kernel, runtime, contract::FailureKind::Quarantine)?;
        return Ok(WorkflowResult {
            disposition: Disposition::Quarantined,
            subject_digest,
            decision_digest: None,
            observation_digest,
        });
    }
    let decision = kernel.admit(proposal, observation.at)?;
    if decision.kind != DecisionKind::Accepted {
        observe_failure(kernel, runtime, contract::FailureKind::Rejection)?;
        return Ok(WorkflowResult {
            disposition: Disposition::Rejected,
            subject_digest,
            decision_digest: Some(decision.decision_digest),
            observation_digest,
        });
    }
    complete_admitted(
        kernel,
        runtime,
        proposal,
        decision,
        subject_digest,
        observation_digest,
        observation,
    )
}

fn complete_admitted(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    proposal: &Proposal,
    decision: crate::Decision,
    subject_digest: String,
    observation_digest: String,
    observation: Observation,
) -> Result<WorkflowResult> {
    runtime.execute(kernel, proposal, &decision, observation.at)?;
    if observation.kill_requested || !observation.healthy || !observation.telemetry_present {
        let rolled_back = runtime.rollback("unhealthy observation");
        if rolled_back {
            kernel.rollback(proposal)?;
        }
        let budget_decision = observe_failure(kernel, runtime, contract::FailureKind::Rollback)?;
        if observation.kill_requested {
            runtime.kill("kill observation");
            kernel.kill(proposal)?;
        } else {
            runtime.freeze("unhealthy observation");
            if budget_decision != contract::BudgetDecision::FreezeRequired {
                kernel.freeze(proposal)?;
            }
        }
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
    kernel.complete(proposal)?;
    kernel.observe_success();
    Ok(WorkflowResult {
        disposition: Disposition::Completed,
        subject_digest,
        decision_digest: Some(decision.decision_digest),
        observation_digest,
    })
}

/// Runs the coordinator path with an independently verified capability
/// receipt before runtime mutation. An invalid receipt quarantines the
/// proposal after the admission record but before capability consumption.
pub fn run_with_receipt(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    evidence: &EvidenceRegistry,
    evidence_id: &str,
    binding: ReceiptBinding<'_>,
    proposal: &Proposal,
    observation: Observation,
) -> Result<WorkflowResult> {
    let subject_digest = proposal.digest()?;
    let observation_digest = digest(&observation)?;
    if !evidence.is_valid(evidence_id, observation.at, &subject_digest) {
        observe_failure(kernel, runtime, contract::FailureKind::Quarantine)?;
        return Ok(WorkflowResult {
            disposition: Disposition::Quarantined,
            subject_digest,
            decision_digest: None,
            observation_digest,
        });
    }
    let decision = kernel.admit(proposal, observation.at)?;
    if decision.kind != DecisionKind::Accepted {
        observe_failure(kernel, runtime, contract::FailureKind::Rejection)?;
        return Ok(WorkflowResult {
            disposition: Disposition::Rejected,
            subject_digest,
            decision_digest: Some(decision.decision_digest),
            observation_digest,
        });
    }
    if binding
        .verifier
        .verify(
            binding.receipt,
            binding.subject,
            proposal,
            &decision,
            &kernel.policy,
            observation.at,
        )
        .is_err()
    {
        kernel.quarantine(proposal)?;
        observe_failure(kernel, runtime, contract::FailureKind::Quarantine)?;
        return Ok(WorkflowResult {
            disposition: Disposition::Quarantined,
            subject_digest,
            decision_digest: Some(decision.decision_digest),
            observation_digest,
        });
    }
    complete_admitted(
        kernel,
        runtime,
        proposal,
        decision,
        subject_digest,
        observation_digest,
        observation,
    )
}

pub fn run_with_artifact(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    binding: EvidenceBinding<'_>,
    proposal: &Proposal,
    observation: Observation,
) -> Result<WorkflowResult> {
    let subject_digest = proposal.digest()?;
    let observation_digest = digest(&observation)?;
    if binding
        .artifacts
        .require_valid(binding.artifact_id, &proposal.source_digest, observation.at)
        .is_err()
    {
        return Ok(WorkflowResult {
            disposition: Disposition::Quarantined,
            subject_digest,
            decision_digest: None,
            observation_digest,
        });
    }
    run(
        kernel,
        runtime,
        binding.evidence,
        binding.evidence_id,
        proposal,
        observation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::ReceiptSigner;
    use crate::{Action, Claim, Evidence, Policy};
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn proposal() -> Proposal {
        Proposal {
            candidate_id: "integration-receipt-candidate".into(),
            agent_id: "integration-agent".into(),
            intent: "write a bounded local value".into(),
            action: Action::Write,
            scope: "public".into(),
            payload: [
                ("key".into(), Value::String("public:receipt".into())),
                ("value".into(), Value::String("verified".into())),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
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
        }
    }

    fn evidence_for(proposal: &Proposal) -> Evidence {
        Evidence {
            id: "integration-receipt-evidence".into(),
            source_digest: proposal.digest().expect("proposal digest"),
            operator_id: "operator".into(),
            validator_id: "validator".into(),
            reviewer_id: "reviewer".into(),
            valid_until: 1_000,
            accepted: true,
            revoked: false,
        }
    }

    #[test]
    fn receipt_is_verified_before_coordinator_execution() {
        let proposal = proposal();
        let policy = Policy::default();
        let mut issuing_kernel = Kernel::new(policy.clone()).expect("issuing kernel");
        let decision = issuing_kernel.admit(&proposal, 10).expect("admit");
        let signer = ReceiptSigner::from_seed("integration-issuer", [9; 32]).expect("signer");
        let receipt = signer
            .issue("tenant-1", &proposal, &decision, &policy)
            .expect("receipt");

        let mut evidence = EvidenceRegistry::default();
        evidence.insert(evidence_for(&proposal)).expect("evidence");
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        let mut kernel = Kernel::new(policy).expect("kernel");
        let mut runtime = Runtime::default();
        let result = run_with_receipt(
            &mut kernel,
            &mut runtime,
            &evidence,
            "integration-receipt-evidence",
            ReceiptBinding {
                verifier: &mut verifier,
                receipt: &receipt,
                subject: "tenant-1",
            },
            &proposal,
            Observation {
                at: 10,
                healthy: true,
                telemetry_present: true,
                kill_requested: false,
            },
        )
        .expect("workflow");
        assert_eq!(result.disposition, Disposition::Completed);
        assert_eq!(
            runtime.state.get("public:receipt"),
            Some(&Value::String("verified".into()))
        );
        assert_eq!(
            kernel.lifecycle_state(&proposal.digest().expect("subject")),
            Some(crate::contract::LifecycleState::Completed)
        );
    }

    #[test]
    fn invalid_receipt_quarantines_without_runtime_mutation() {
        let proposal = proposal();
        let policy = Policy::default();
        let mut issuing_kernel = Kernel::new(policy.clone()).expect("issuing kernel");
        let decision = issuing_kernel.admit(&proposal, 10).expect("admit");
        let signer = ReceiptSigner::from_seed("integration-issuer", [9; 32]).expect("signer");
        let receipt = signer
            .issue("tenant-1", &proposal, &decision, &policy)
            .expect("receipt");
        let mut evidence = EvidenceRegistry::default();
        evidence.insert(evidence_for(&proposal)).expect("evidence");
        let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
            .expect("verifier");
        let mut kernel = Kernel::new(policy).expect("kernel");
        let mut runtime = Runtime::default();
        let result = run_with_receipt(
            &mut kernel,
            &mut runtime,
            &evidence,
            "integration-receipt-evidence",
            ReceiptBinding {
                verifier: &mut verifier,
                receipt: &receipt,
                subject: "tenant-2",
            },
            &proposal,
            Observation {
                at: 10,
                healthy: true,
                telemetry_present: true,
                kill_requested: false,
            },
        )
        .expect("workflow");
        assert_eq!(result.disposition, Disposition::Quarantined);
        assert!(runtime.state.is_empty());
        assert!(runtime.audit.is_empty());
        assert_eq!(
            kernel.lifecycle_state(&proposal.digest().expect("subject")),
            Some(crate::contract::LifecycleState::Quarantined)
        );
    }

    #[test]
    fn exhausted_failure_budget_freezes_runtime_before_returning_error() {
        let mut kernel = Kernel::new(Policy::default()).expect("kernel");
        kernel
            .configure_failure_budget(crate::contract::FailureBudget {
                max_rejections: 10,
                max_quarantines: 1,
                max_rollbacks: 10,
                max_consecutive_failures: 10,
                max_window_failures: 10,
                window_size: 10,
            })
            .expect("budget");
        kernel
            .observe_failure(crate::contract::FailureKind::Quarantine)
            .expect("first failure");
        let mut runtime = Runtime::default();
        let error = run(
            &mut kernel,
            &mut runtime,
            &EvidenceRegistry::default(),
            "missing",
            &proposal(),
            Observation {
                at: 10,
                healthy: true,
                telemetry_present: true,
                kill_requested: false,
            },
        );
        assert!(error.is_err());
        assert!(runtime.is_frozen());
        assert!(kernel.is_frozen());
    }
}
