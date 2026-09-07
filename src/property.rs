//! Deterministic property checks for the Phase 0 contract and local kernel.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The checks enumerate the complete finite lifecycle table and the complete
//! eight-atom capability powerset. Kernel checks use only local public control
//! plane APIs. Returned records contain property identifiers, booleans, and
//! digests; they do not retain proposals, state, payloads, or raw failures.
//! These are regression checks, not formal proofs or evidence of an external
//! sandbox, provider, model, or authenticated identity.

use crate::contract::{
    transition, Authority, CapabilitySet, Lifecycle, LifecycleEvent, LifecycleState,
};
use crate::{digest, Action, Claim, DecisionKind, Kernel, Policy, Proposal, Result, Runtime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const STATE_SLICE: &str = "security-alignment-os-foundation-v1";
const AUTHORITY_COUNT: usize = 8;
const LIFECYCLE_STATE_COUNT: usize = 9;
const LIFECYCLE_EVENT_COUNT: usize = 8;

/// A digest-only result for one deterministic property.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PropertyOutcome {
    pub property_id: String,
    pub passed: bool,
    pub evidence_digest: String,
}

impl PropertyOutcome {
    fn new<T: Serialize>(property_id: &str, passed: bool, evidence: &T) -> Result<Self> {
        Ok(Self {
            property_id: property_id.into(),
            passed,
            evidence_digest: digest(&(STATE_SLICE, property_id, passed, evidence))?,
        })
    }
}

/// A deterministic digest-only report over one complete property run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckReport {
    pub state_slice: String,
    pub outcomes: Vec<PropertyOutcome>,
    pub passed: u32,
    pub failed: u32,
    pub report_digest: String,
}

impl CheckReport {
    fn from_outcomes(outcomes: Vec<PropertyOutcome>) -> Result<Self> {
        let mut ids = BTreeSet::new();
        for outcome in &outcomes {
            if outcome.property_id.is_empty() || !ids.insert(outcome.property_id.clone()) {
                return Err(crate::Error::Invalid(
                    "property identifiers must be non-empty and unique".into(),
                ));
            }
        }
        let passed = outcomes.iter().filter(|outcome| outcome.passed).count() as u32;
        let failed = outcomes.len() as u32 - passed;
        let state_slice = STATE_SLICE.into();
        let report_digest = digest(&(&state_slice, &outcomes, passed, failed))?;
        Ok(Self {
            state_slice,
            outcomes,
            passed,
            failed,
            report_digest,
        })
    }

    /// Recomputes the report commitment and validates its public counters.
    pub fn validate(&self) -> Result<()> {
        if self.state_slice != STATE_SLICE
            || self
                .outcomes
                .iter()
                .any(|outcome| outcome.property_id.is_empty())
            || self
                .outcomes
                .iter()
                .map(|outcome| outcome.property_id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                != self.outcomes.len()
        {
            return Err(crate::Error::Invalid("invalid property report".into()));
        }
        let passed = self
            .outcomes
            .iter()
            .filter(|outcome| outcome.passed)
            .count() as u32;
        let failed = self.outcomes.len() as u32 - passed;
        if self.passed != passed || self.failed != failed {
            return Err(crate::Error::Invalid(
                "property counters do not match".into(),
            ));
        }
        let expected = digest(&(&self.state_slice, &self.outcomes, self.passed, self.failed))?;
        if self.report_digest != expected {
            return Err(crate::Error::Invalid(
                "property report digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn lifecycle_states() -> [LifecycleState; LIFECYCLE_STATE_COUNT] {
    [
        LifecycleState::Proposal,
        LifecycleState::Quarantined,
        LifecycleState::Rejected,
        LifecycleState::Admitted,
        LifecycleState::Executing,
        LifecycleState::Completed,
        LifecycleState::RolledBack,
        LifecycleState::Frozen,
        LifecycleState::Killed,
    ]
}

fn lifecycle_events() -> [LifecycleEvent; LIFECYCLE_EVENT_COUNT] {
    [
        LifecycleEvent::Quarantine,
        LifecycleEvent::Reject,
        LifecycleEvent::Admit,
        LifecycleEvent::BeginExecution,
        LifecycleEvent::Complete,
        LifecycleEvent::Rollback,
        LifecycleEvent::Freeze,
        LifecycleEvent::Kill,
    ]
}

/// Independent expected table used to test `contract::transition`.
fn expected_transition(state: LifecycleState, event: LifecycleEvent) -> Option<LifecycleState> {
    use LifecycleEvent::{
        Admit, BeginExecution, Complete, Freeze, Kill, Quarantine, Reject, Rollback,
    };
    use LifecycleState::{
        Admitted, Completed, Executing, Frozen, Killed, Proposal, Quarantined, Rejected, RolledBack,
    };

    match (state, event) {
        (Proposal, Quarantine) => Some(Quarantined),
        (Proposal, Reject) => Some(Rejected),
        (Proposal, Admit) => Some(Admitted),
        (Quarantined, Reject) => Some(Rejected),
        (Quarantined, Admit) => Some(Admitted),
        (Admitted, Quarantine) => Some(Quarantined),
        (Admitted, BeginExecution) => Some(Executing),
        (Executing, Complete) => Some(Completed),
        (Executing, Rollback) => Some(RolledBack),
        (Completed, Rollback) => Some(RolledBack),
        (RolledBack, Admit) => Some(Admitted),
        (
            Proposal | Quarantined | Rejected | Admitted | Executing | Completed | RolledBack,
            Freeze,
        ) => Some(Frozen),
        (
            Proposal | Quarantined | Rejected | Admitted | Executing | Completed | RolledBack
            | Frozen,
            Kill,
        ) => Some(Killed),
        _ => None,
    }
}

/// Exhaustively checks all 9 x 8 lifecycle state/event pairs.
pub fn check_lifecycle_transitions() -> Result<PropertyOutcome> {
    let states = lifecycle_states();
    let events = lifecycle_events();
    let mut mismatches = 0u32;
    let mut checked = 0u32;
    for state in states {
        for event in events {
            checked = checked.saturating_add(1);
            let expected = expected_transition(state, event);
            let actual = transition(state, event).ok();
            if actual != expected {
                mismatches = mismatches.saturating_add(1);
            }

            let mut lifecycle = Lifecycle { state, revision: 7 };
            let before = lifecycle.clone();
            match expected {
                Some(next) => {
                    if lifecycle.apply(event).ok() != Some(next) || lifecycle.revision != 8 {
                        mismatches = mismatches.saturating_add(1);
                    }
                }
                None => {
                    if lifecycle.apply(event).is_ok() || lifecycle != before {
                        mismatches = mismatches.saturating_add(1);
                    }
                }
            }
        }
    }
    PropertyOutcome::new(
        "phase0.lifecycle_transition_table",
        mismatches == 0,
        &(checked, mismatches),
    )
}

fn capability_for_mask(mask: u16) -> CapabilitySet {
    let authorities = Authority::all();
    let selected: Vec<_> = authorities
        .iter()
        .enumerate()
        .filter_map(|(index, authority)| (mask & (1u16 << index) != 0).then_some(*authority))
        .collect();
    CapabilitySet::from_slice(&selected)
}

fn mask_for_capability(set: &CapabilitySet) -> u16 {
    let mut mask = 0u16;
    for authority in set.iter() {
        if let Some(index) = Authority::all()
            .iter()
            .position(|candidate| candidate == authority)
        {
            mask |= 1u16 << index;
        }
    }
    mask
}

/// Exhaustively checks all elements and binary operations of the authority
/// powerset lattice (256 elements and 65,536 ordered pairs).
pub fn check_authority_powerset() -> Result<PropertyOutcome> {
    let element_count = 1usize << AUTHORITY_COUNT;
    let mut mismatches = 0u32;
    let mut checked = 0u32;
    for left_mask in 0..element_count {
        let left = capability_for_mask(left_mask as u16);
        if mask_for_capability(&left) != left_mask as u16
            || left.len() != left_mask.count_ones() as usize
        {
            mismatches = mismatches.saturating_add(1);
        }
        for right_mask in 0..element_count {
            checked = checked.saturating_add(1);
            let right = capability_for_mask(right_mask as u16);
            let expected_leq = (left_mask & !right_mask) == 0;
            if left.leq(&right) != expected_leq
                || right.covers(&left) != expected_leq
                || mask_for_capability(&left.join(&right)) != (left_mask | right_mask) as u16
                || mask_for_capability(&left.meet(&right)) != (left_mask & right_mask) as u16
            {
                mismatches = mismatches.saturating_add(1);
            }
        }
    }
    PropertyOutcome::new(
        "phase0.authority_powerset",
        mismatches == 0,
        &(element_count as u32, checked, mismatches),
    )
}

/// Checks that each singleton authority is incomparable with every other
/// singleton; there are no implicit authority implication edges.
pub fn check_authority_nonimplication() -> Result<PropertyOutcome> {
    let authorities = Authority::all();
    let mut checked = 0u32;
    let mut mismatches = 0u32;
    for (left_index, left_authority) in authorities.iter().enumerate() {
        for (right_index, right_authority) in authorities.iter().enumerate() {
            if left_index == right_index {
                continue;
            }
            checked = checked.saturating_add(1);
            let left = CapabilitySet::from_slice(&[*left_authority]);
            let right = CapabilitySet::from_slice(&[*right_authority]);
            if left.covers(&right) || right.covers(&left) {
                mismatches = mismatches.saturating_add(1);
            }
        }
    }
    PropertyOutcome::new(
        "phase0.authority_singleton_nonimplication",
        mismatches == 0,
        &(checked, mismatches),
    )
}

fn valid_claim() -> Claim {
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

fn valid_proposal(candidate_id: &str) -> Proposal {
    Proposal {
        candidate_id: candidate_id.into(),
        agent_id: "property-agent".into(),
        intent: "write-local-value".into(),
        action: Action::Write,
        scope: "sandbox".into(),
        payload: [
            ("key".into(), Value::String("sandbox:key".into())),
            ("value".into(), Value::Number(1.into())),
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
        claims: vec![valid_claim()],
        nonce: 1,
        expires_at: 50,
        requests_direct_authority: false,
    }
}

/// An accepted decision rejected by the runtime must leave runtime state and
/// audit data unchanged. A rejection journal record is expected bookkeeping.
pub fn check_rejection_cannot_mutate_state() -> Result<PropertyOutcome> {
    let mut proposal = valid_proposal("property-rejection");
    proposal.requests_direct_authority = true;
    let mut kernel = Kernel::new(Policy::default())?;
    let mut runtime = Runtime::default();
    let before_state = digest(&runtime.state)?;
    let before_audit = digest(&runtime.audit)?;
    let decision = kernel.admit(&proposal, 10)?;
    let executed = runtime.execute(&mut kernel, &proposal, &decision, 10)?;
    let passed = decision.kind == DecisionKind::Rejected
        && !executed
        && digest(&runtime.state)? == before_state
        && digest(&runtime.audit)? == before_audit;
    PropertyOutcome::new(
        "kernel.rejection_cannot_mutate_runtime",
        passed,
        &(
            decision.kind,
            executed,
            runtime.state.len(),
            runtime.audit.len(),
        ),
    )
}

/// An expired capability must be rejected before reservation or runtime
/// mutation.
pub fn check_expired_capability_cannot_execute() -> Result<PropertyOutcome> {
    let proposal = valid_proposal("property-expiry");
    let mut kernel = Kernel::new(Policy::default())?;
    let mut runtime = Runtime::default();
    let decision = kernel.admit(&proposal, 10)?;
    let before_state = digest(&runtime.state)?;
    let before_audit = digest(&runtime.audit)?;
    let attempted = runtime.execute(&mut kernel, &proposal, &decision, 40);
    let passed = attempted.is_err()
        && digest(&runtime.state)? == before_state
        && digest(&runtime.audit)? == before_audit;
    PropertyOutcome::new(
        "kernel.expired_capability_cannot_execute",
        passed,
        &(attempted.is_err(), runtime.state.len(), runtime.audit.len()),
    )
}

/// The kill path must close execution before capability consumption.
pub fn check_kill_closes_execution() -> Result<PropertyOutcome> {
    let proposal = valid_proposal("property-kill");
    let mut kernel = Kernel::new(Policy::default())?;
    let mut runtime = Runtime::default();
    let decision = kernel.admit(&proposal, 10)?;
    let before_state = digest(&runtime.state)?;
    let before_journal = digest(&kernel.journal)?;
    runtime.kill("property-kill");
    let attempted = runtime.execute(&mut kernel, &proposal, &decision, 10);
    let passed = runtime.is_killed()
        && attempted.is_err()
        && digest(&runtime.state)? == before_state
        && digest(&kernel.journal)? == before_journal;
    PropertyOutcome::new(
        "kernel.kill_closes_execution",
        passed,
        &(
            runtime.is_killed(),
            attempted.is_err(),
            runtime.state.len(),
            kernel.journal.entries.len(),
        ),
    )
}

/// Runs every deterministic Phase 0 and kernel property check in fixed order.
pub fn run_all() -> Result<CheckReport> {
    CheckReport::from_outcomes(vec![
        check_lifecycle_transitions()?,
        check_authority_powerset()?,
        check_authority_nonimplication()?,
        check_rejection_cannot_mutate_state()?,
        check_expired_capability_cannot_execute()?,
        check_kill_closes_execution()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_check_is_exhaustive_and_passes() {
        let outcome = check_lifecycle_transitions().unwrap();
        assert!(outcome.passed);
        assert_eq!(outcome.property_id, "phase0.lifecycle_transition_table");
    }

    #[test]
    fn authority_powerset_check_is_exhaustive_and_passes() {
        let outcome = check_authority_powerset().unwrap();
        assert!(outcome.passed);
        assert_eq!(outcome.property_id, "phase0.authority_powerset");
    }

    #[test]
    fn authority_atoms_have_no_implicit_implication() {
        assert!(check_authority_nonimplication().unwrap().passed);
    }

    #[test]
    fn rejection_cannot_mutate_runtime_state() {
        assert!(check_rejection_cannot_mutate_state().unwrap().passed);
    }

    #[test]
    fn expired_capability_cannot_execute() {
        assert!(check_expired_capability_cannot_execute().unwrap().passed);
    }

    #[test]
    fn kill_closes_execution() {
        assert!(check_kill_closes_execution().unwrap().passed);
    }

    #[test]
    fn report_is_digest_bound_and_deterministic() {
        let first = run_all().unwrap();
        let second = run_all().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.failed, 0);
        assert_eq!(first.passed, 6);
        first.validate().unwrap();
    }

    #[test]
    fn report_rejects_counter_tampering() {
        let mut report = run_all().unwrap();
        report.passed = report.passed.saturating_add(1);
        assert!(report.validate().is_err());
    }
}
