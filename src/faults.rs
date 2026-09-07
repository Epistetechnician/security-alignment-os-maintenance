//! Deterministic local fault-injection scenarios for the foundation slice.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module is intentionally standalone. The library keeps its public
//! surface unchanged while the integration test includes this file directly.
//! Each scenario exercises only the existing local control-plane APIs and
//! returns digests plus a fail-closed disposition. It never starts a process,
//! contacts a provider, opens a network connection, or executes a model.

use crate::{
    digest, digest_bytes, integration, Error, EvidenceRegistry, Kernel, Proposal, ReplayJournal,
    Result, Runtime,
};
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum FaultScenario {
    Replay,
    StaleClock,
    StalePolicyDigest,
    MalformedJournalBytes,
    PartialWrite,
    KillFreezeObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum FaultDisposition {
    Rejected,
    Quarantined,
    RolledBack,
    Frozen,
    NotDetected,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct FaultOutcome {
    pub scenario: FaultScenario,
    pub disposition: FaultDisposition,
    pub input_digest: String,
    pub detail_digest: String,
}

fn outcome(
    scenario: FaultScenario,
    disposition: FaultDisposition,
    input_digest: String,
    detail: &str,
) -> Result<FaultOutcome> {
    Ok(FaultOutcome {
        scenario,
        disposition,
        input_digest,
        detail_digest: digest(&(scenario, detail))?,
    })
}

/// Admits a proposal twice and classifies the second journal append as a
/// replay rejection. Both exact candidate replay and same-agent nonce replay
/// must not append a second entry.
pub fn replay(kernel: &mut Kernel, proposal: &Proposal, now: u64) -> Result<FaultOutcome> {
    let input_digest = proposal.digest()?;
    let _first = kernel.admit(proposal, now)?;
    let mut changed = proposal.clone();
    changed.candidate_id.push_str("-changed");
    let second = kernel.admit(&changed, now);
    match second {
        Err(Error::Journal(_)) => outcome(
            FaultScenario::Replay,
            FaultDisposition::Rejected,
            input_digest,
            "duplicate-agent-nonce-rejected",
        ),
        Ok(_) => outcome(
            FaultScenario::Replay,
            FaultDisposition::NotDetected,
            input_digest,
            "duplicate-agent-nonce-was-accepted",
        ),
        Err(_) => outcome(
            FaultScenario::Replay,
            FaultDisposition::Quarantined,
            input_digest,
            "duplicate-agent-nonce-reached-unexpected-error",
        ),
    }
}

/// Attempts execution after the capability's expiry time. The runtime must
/// reject before consuming the capability or changing state.
pub fn stale_clock(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    proposal: &Proposal,
    admitted_at: u64,
    stale_now: u64,
) -> Result<FaultOutcome> {
    let input_digest = proposal.digest()?;
    let decision = kernel.admit(proposal, admitted_at)?;
    let before_state = digest(&runtime.state)?;
    let before_audit = runtime.audit.len();
    let attempted = runtime.execute(kernel, proposal, &decision, stale_now);
    let after_state = digest(&runtime.state)?;
    let disposition =
        if attempted.is_err() && before_state == after_state && before_audit == runtime.audit.len()
        {
            FaultDisposition::Rejected
        } else {
            FaultDisposition::NotDetected
        };
    outcome(
        FaultScenario::StaleClock,
        disposition,
        input_digest,
        if disposition == FaultDisposition::Rejected {
            "expired-capability-rejected-before-mutation"
        } else {
            "expired-capability-mutated-or-was-accepted"
        },
    )
}

/// Changes the policy after admission and verifies that kernel consumption is
/// quarantined while the decision carries a stale policy digest.
pub fn stale_policy_digest(
    kernel: &mut Kernel,
    proposal: &Proposal,
    now: u64,
) -> Result<FaultOutcome> {
    let input_digest = proposal.digest()?;
    let original_policy = kernel.policy.clone();
    let decision = kernel.admit(proposal, now)?;
    let mut changed_policy = original_policy.clone();
    changed_policy.token_ttl = changed_policy.token_ttl.saturating_add(1);
    kernel.policy = changed_policy;
    let current_policy_digest = digest(&kernel.policy)?;
    let consumed = kernel.consume(proposal, &decision, now)?;
    let stale = decision.policy_digest != current_policy_digest
        && !consumed
        && kernel.lifecycle_state(&input_digest)
            == Some(crate::contract::LifecycleState::Quarantined);
    kernel.policy = original_policy;
    outcome(
        FaultScenario::StalePolicyDigest,
        if stale {
            FaultDisposition::Quarantined
        } else {
            FaultDisposition::NotDetected
        },
        input_digest,
        if stale {
            "decision-policy-digest-quarantined"
        } else {
            "decision-policy-digest-was-not-quarantined"
        },
    )
}

/// Loads caller-provided journal bytes through the canonical journal loader.
/// Any parse, canonicalization, or chain failure is quarantined; raw bytes are
/// represented only by their SHA-256 digest in the returned record.
pub fn malformed_journal_bytes(path: &Path) -> Result<FaultOutcome> {
    let bytes = fs::read(path)?;
    let input_digest = digest_bytes(&bytes);
    let loaded = ReplayJournal::load(path);
    let disposition = if loaded.is_err() {
        FaultDisposition::Quarantined
    } else {
        FaultDisposition::NotDetected
    };
    outcome(
        FaultScenario::MalformedJournalBytes,
        disposition,
        input_digest,
        if disposition == FaultDisposition::Quarantined {
            "journal-bytes-quarantined"
        } else {
            "journal-bytes-canonical-and-valid"
        },
    )
}

/// Executes one valid local write, then simulates a downstream partial-write
/// failure by invoking the runtime's latest-checkpoint rollback. Success is
/// reported only when the pre-write state digest is restored.
pub fn partial_write(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    proposal: &Proposal,
    now: u64,
) -> Result<FaultOutcome> {
    let input_digest = proposal.digest()?;
    let decision = kernel.admit(proposal, now)?;
    let before_state = digest(&runtime.state)?;
    let executed = runtime.execute(kernel, proposal, &decision, now)?;
    let rolled_back = runtime.rollback("fault-injection:partial-write");
    let after_state = digest(&runtime.state)?;
    let disposition = if executed && rolled_back && before_state == after_state {
        FaultDisposition::RolledBack
    } else {
        FaultDisposition::Quarantined
    };
    outcome(
        FaultScenario::PartialWrite,
        disposition,
        input_digest,
        if disposition == FaultDisposition::RolledBack {
            "partial-write-restored-checkpoint"
        } else {
            "partial-write-checkpoint-not-restored"
        },
    )
}

/// Runs the coordinator with a caller-supplied kill or unhealthy observation.
/// An explicit kill observation is escalated through the public kill path
/// after coordinator rollback; an unhealthy observation remains frozen.
pub fn kill_freeze_observation(
    kernel: &mut Kernel,
    runtime: &mut Runtime,
    evidence: &EvidenceRegistry,
    evidence_id: &str,
    proposal: &Proposal,
    observation: integration::Observation,
) -> Result<FaultOutcome> {
    let input_digest = proposal.digest()?;
    let kill_requested = observation.kill_requested;
    let freeze_requested = kill_requested || !observation.healthy || !observation.telemetry_present;
    let result = integration::run(
        kernel,
        runtime,
        evidence,
        evidence_id,
        proposal,
        observation,
    )?;
    if kill_requested && result.disposition == integration::Disposition::RolledBack {
        runtime.kill("fault-injection:kill-observation");
    }
    let disposition = if result.disposition == integration::Disposition::RolledBack
        && freeze_requested
        && runtime.is_frozen()
        && (!kill_requested || runtime.is_killed())
    {
        FaultDisposition::Frozen
    } else {
        FaultDisposition::NotDetected
    };
    outcome(
        FaultScenario::KillFreezeObservation,
        disposition,
        input_digest,
        if disposition == FaultDisposition::Frozen {
            "kill-observation-rolled-back-and-froze-runtime"
        } else {
            "kill-observation-did-not-close-runtime"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest, Action, Claim, Evidence, Policy};
    use serde_json::Value;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn claim() -> Claim {
        Claim {
            guarantees: vec!["PolicyCompliance".into()],
            assumptions: vec![],
            excludes: vec!["alignment".into()],
            maturity: 1,
            trust_roots: vec!["local".into()],
            valid_until: 1_000,
            provenance_digest: "a".repeat(64),
        }
    }

    fn proposal(id: &str) -> Proposal {
        Proposal {
            candidate_id: id.into(),
            agent_id: "fault-agent".into(),
            intent: "write-local-test-value".into(),
            action: Action::Write,
            scope: "sandbox".into(),
            payload: [
                ("key".into(), Value::String("sandbox:fault".into())),
                ("value".into(), Value::String("local".into())),
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
            source_digest: "b".repeat(64),
            claims: vec![claim()],
            nonce: 1,
            expires_at: 900,
            requests_direct_authority: false,
        }
    }

    fn accepted_evidence(proposal: &Proposal) -> (EvidenceRegistry, String) {
        let subject = proposal.digest().unwrap();
        let mut registry = EvidenceRegistry::default();
        registry
            .insert(Evidence {
                id: "fault-evidence".into(),
                source_digest: subject,
                operator_id: "operator".into(),
                validator_id: "validator".into(),
                reviewer_id: "".into(),
                valid_until: 900,
                accepted: false,
                revoked: false,
            })
            .unwrap();
        registry.accept("fault-evidence", "reviewer").unwrap();
        (registry, "fault-evidence".into())
    }

    fn assert_digest(value: &str) {
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!value.bytes().any(|byte| byte.is_ascii_uppercase()));
    }

    #[test]
    fn replay_is_rejected_without_a_second_entry() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let result = replay(&mut kernel, &proposal("replay"), 10).unwrap();
        assert_eq!(result.disposition, FaultDisposition::Rejected);
        assert_eq!(kernel.journal.entries.len(), 1);
        assert_digest(&result.input_digest);
        assert_digest(&result.detail_digest);
    }

    #[test]
    fn stale_clock_rejects_before_runtime_mutation() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let result = stale_clock(&mut kernel, &mut runtime, &proposal("clock"), 10, 41).unwrap();
        assert_eq!(result.disposition, FaultDisposition::Rejected);
        assert!(runtime.state.is_empty());
        assert!(runtime.audit.is_empty());
    }

    #[test]
    fn stale_policy_is_quarantined_before_execution() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let result = stale_policy_digest(&mut kernel, &proposal("policy"), 10).unwrap();
        assert_eq!(result.disposition, FaultDisposition::Quarantined);
        assert_eq!(kernel.policy, Policy::default());
    }

    #[test]
    fn malformed_journal_bytes_are_quarantined() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let proposal = proposal("journal");
        kernel.admit(&proposal, 10).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.json");
        kernel.journal.save(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b' ');
        std::fs::write(&path, bytes).unwrap();
        let result = malformed_journal_bytes(&path).unwrap();
        assert_eq!(result.disposition, FaultDisposition::Quarantined);
    }

    #[test]
    fn partial_write_restores_the_latest_checkpoint() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let result = partial_write(&mut kernel, &mut runtime, &proposal("partial"), 10).unwrap();
        assert_eq!(result.disposition, FaultDisposition::RolledBack);
        assert!(runtime.state.is_empty());
    }

    #[test]
    fn kill_observation_rolls_back_and_freezes() {
        let mut kernel = Kernel::new(Policy::default()).unwrap();
        let mut runtime = Runtime::default();
        let proposal = proposal("kill");
        let (evidence, evidence_id) = accepted_evidence(&proposal);
        let result = kill_freeze_observation(
            &mut kernel,
            &mut runtime,
            &evidence,
            &evidence_id,
            &proposal,
            integration::Observation {
                at: 10,
                healthy: true,
                telemetry_present: true,
                kill_requested: true,
            },
        )
        .unwrap();
        assert_eq!(result.disposition, FaultDisposition::Frozen);
        assert!(runtime.is_killed());
        assert!(runtime.is_frozen());
        assert!(runtime.state.is_empty());
    }

    #[test]
    fn outcomes_do_not_include_raw_fault_payloads() {
        let p = proposal("digest-only");
        let outcome = FaultOutcome {
            scenario: FaultScenario::Replay,
            disposition: FaultDisposition::Rejected,
            input_digest: digest(&p).unwrap(),
            detail_digest: digest(&(FaultScenario::Replay, "duplicate-candidate-rejected"))
                .unwrap(),
        };
        let encoded = serde_json::to_string(&outcome).unwrap();
        assert!(!encoded.contains("sandbox:fault"));
        assert!(!encoded.contains("write-local-test-value"));
        assert!(!encoded.contains("duplicate-candidate-rejected"));
        let _: BTreeMap<String, serde_json::Value> = serde_json::from_str(&encoded).unwrap();
    }
}
