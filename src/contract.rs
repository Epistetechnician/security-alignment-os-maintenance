//! Phase 0 contract types for the local security-alignment control plane.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module is intentionally independent of the runtime implementation. It
//! defines the authority vocabulary, lifecycle transition table, and
//! caller-owned failure budget that an integration layer can wire into the
//! kernel. Capability sets are a powerset lattice: no capability silently
//! implies another capability.

use crate::{canonical_bytes, Error as CrateError, Result as CrateResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const STATE_SLICE: &str = "security-alignment-os-foundation-v1";

/// The complete authority vocabulary for the foundation slice.
///
/// These are deliberately independent atoms. In particular, `Secrets` does
/// not imply `Read`, `Execute` does not imply `Write`, and `SelfModify` does
/// not imply any other authority. A caller must request and receive each
/// capability explicitly.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Authority {
    Read,
    Write,
    Network,
    Secrets,
    Spend,
    Replicate,
    Execute,
    SelfModify,
}

impl Authority {
    /// Returns every atom in the fixed lattice order.
    pub const fn all() -> [Self; 8] {
        [
            Self::Read,
            Self::Write,
            Self::Network,
            Self::Secrets,
            Self::Spend,
            Self::Replicate,
            Self::Execute,
            Self::SelfModify,
        ]
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Network => "network",
            Self::Secrets => "secrets",
            Self::Spend => "spend",
            Self::Replicate => "replicate",
            Self::Execute => "execute",
            Self::SelfModify => "self_modify",
        };
        formatter.write_str(name)
    }
}

/// A capability set in the explicit powerset lattice.
///
/// The bottom element is the empty set, the top element is `all`, `join` is
/// set union, `meet` is set intersection, and `leq` is subset inclusion.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilitySet {
    authorities: BTreeSet<Authority>,
}

impl CapabilitySet {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn all() -> Self {
        Self {
            authorities: Authority::all().into_iter().collect(),
        }
    }

    pub fn from_slice(authorities: &[Authority]) -> Self {
        Self {
            authorities: authorities.iter().copied().collect(),
        }
    }

    pub fn contains(&self, authority: Authority) -> bool {
        self.authorities.contains(&authority)
    }

    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }

    pub fn len(&self) -> usize {
        self.authorities.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Authority> {
        self.authorities.iter()
    }

    /// Returns whether this set is below or equal to `other` in the lattice.
    pub fn leq(&self, other: &Self) -> bool {
        self.authorities.is_subset(&other.authorities)
    }

    /// Returns whether `self` contains every authority in `requested`.
    pub fn covers(&self, requested: &Self) -> bool {
        requested.leq(self)
    }

    pub fn join(&self, other: &Self) -> Self {
        Self {
            authorities: self
                .authorities
                .union(&other.authorities)
                .copied()
                .collect(),
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        Self {
            authorities: self
                .authorities
                .intersection(&other.authorities)
                .copied()
                .collect(),
        }
    }
}

/// Lifecycle states for one proposal/capability execution record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LifecycleState {
    Proposal,
    Quarantined,
    Rejected,
    Admitted,
    Executing,
    Completed,
    RolledBack,
    Frozen,
    Killed,
}

impl LifecycleState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Rejected | Self::Frozen | Self::Killed)
    }

    pub fn is_shutdown(self) -> bool {
        matches!(self, Self::Frozen | Self::Killed)
    }
}

/// Events accepted by the lifecycle transition function.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LifecycleEvent {
    Quarantine,
    Reject,
    Admit,
    BeginExecution,
    Complete,
    Rollback,
    Freeze,
    Kill,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("invalid lifecycle transition from {state:?} on {event:?}")]
    InvalidTransition {
        state: LifecycleState,
        event: LifecycleEvent,
    },
    #[error("failure budget is invalid: {0}")]
    InvalidBudget(String),
    #[error("failure budget is already exhausted")]
    BudgetExhausted,
}

/// The frozen lifecycle transition table.
pub fn transition(
    state: LifecycleState,
    event: LifecycleEvent,
) -> Result<LifecycleState, ContractError> {
    use LifecycleEvent::{
        Admit, BeginExecution, Complete, Freeze, Kill, Quarantine, Reject, Rollback,
    };
    use LifecycleState::{
        Admitted, Completed, Executing, Frozen, Killed, Proposal, Quarantined, Rejected, RolledBack,
    };

    let next = match (state, event) {
        (Proposal, Quarantine) => Quarantined,
        (Proposal, Reject) => Rejected,
        (Proposal, Admit) => Admitted,
        (Quarantined, Reject) => Rejected,
        (Quarantined, Admit) => Admitted,
        (Admitted, Quarantine) => Quarantined,
        (Admitted, BeginExecution) => Executing,
        (Executing, Complete) => Completed,
        (Executing, Rollback) => RolledBack,
        (Completed, Rollback) => RolledBack,
        (RolledBack, Admit) => Admitted,
        (
            Proposal | Quarantined | Rejected | Admitted | Executing | Completed | RolledBack,
            Freeze,
        ) => Frozen,
        (
            Proposal | Quarantined | Rejected | Admitted | Executing | Completed | RolledBack
            | Frozen,
            Kill,
        ) => Killed,
        _ => {
            return Err(ContractError::InvalidTransition { state, event });
        }
    };
    Ok(next)
}

/// A caller-owned state-machine instance with a monotonic transition number.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Lifecycle {
    pub state: LifecycleState,
    pub revision: u64,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: LifecycleState::Proposal,
            revision: 0,
        }
    }
}

impl Lifecycle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: LifecycleEvent) -> Result<LifecycleState, ContractError> {
        let next = transition(self.state, event)?;
        self.state = next;
        self.revision = self.revision.saturating_add(1);
        Ok(next)
    }
}

/// Failure categories counted by the foundation freeze policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FailureKind {
    Rejection,
    Quarantine,
    Rollback,
}

/// Inclusive ceilings for caller-owned failure accounting.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureBudget {
    pub max_rejections: u32,
    pub max_quarantines: u32,
    pub max_rollbacks: u32,
    pub max_consecutive_failures: u32,
    pub max_window_failures: u32,
    pub window_size: u32,
}

impl FailureBudget {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.window_size == 0 {
            return Err(ContractError::InvalidBudget(
                "window_size must be positive".into(),
            ));
        }
        if self.max_window_failures > self.window_size {
            return Err(ContractError::InvalidBudget(
                "max_window_failures cannot exceed window_size".into(),
            ));
        }
        Ok(())
    }

    pub fn tracker(&self) -> Result<FailureTracker, ContractError> {
        self.validate()?;
        Ok(FailureTracker {
            budget: self.clone(),
            rejections: 0,
            quarantines: 0,
            rollbacks: 0,
            consecutive_failures: 0,
            recent: Vec::new(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BudgetDecision {
    Continue,
    FreezeRequired,
}

/// Mutable observation state kept separately from the validated budget.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureTracker {
    pub budget: FailureBudget,
    pub rejections: u32,
    pub quarantines: u32,
    pub rollbacks: u32,
    pub consecutive_failures: u32,
    pub recent: Vec<FailureKind>,
}

impl FailureTracker {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.budget.validate()?;
        if self.recent.len() > self.budget.window_size as usize {
            return Err(ContractError::InvalidBudget(
                "recent failure window exceeds its budget".into(),
            ));
        }
        let total =
            u64::from(self.rejections) + u64::from(self.quarantines) + u64::from(self.rollbacks);
        if u64::from(self.consecutive_failures) > total
            || (self.recent.is_empty() && self.consecutive_failures > 0)
        {
            return Err(ContractError::InvalidBudget(
                "failure counters are inconsistent".into(),
            ));
        }
        Ok(())
    }

    pub fn record_failure(&mut self, kind: FailureKind) -> Result<BudgetDecision, ContractError> {
        self.validate()?;
        if self.is_exhausted() {
            return Err(ContractError::BudgetExhausted);
        }

        match kind {
            FailureKind::Rejection => {
                self.rejections = self.rejections.checked_add(1).ok_or_else(|| {
                    ContractError::InvalidBudget("rejection counter overflow".into())
                })?
            }
            FailureKind::Quarantine => {
                self.quarantines = self.quarantines.checked_add(1).ok_or_else(|| {
                    ContractError::InvalidBudget("quarantine counter overflow".into())
                })?
            }
            FailureKind::Rollback => {
                self.rollbacks = self.rollbacks.checked_add(1).ok_or_else(|| {
                    ContractError::InvalidBudget("rollback counter overflow".into())
                })?
            }
        }
        self.consecutive_failures = self.consecutive_failures.checked_add(1).ok_or_else(|| {
            ContractError::InvalidBudget("consecutive failure counter overflow".into())
        })?;
        self.recent.push(kind);
        let window = self.budget.window_size as usize;
        if self.recent.len() > window {
            let excess = self.recent.len() - window;
            self.recent.drain(..excess);
        }
        self.validate()?;

        Ok(if self.is_exhausted() {
            BudgetDecision::FreezeRequired
        } else {
            BudgetDecision::Continue
        })
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn is_exhausted(&self) -> bool {
        Self::at_or_over(self.rejections, self.budget.max_rejections)
            || Self::at_or_over(self.quarantines, self.budget.max_quarantines)
            || Self::at_or_over(self.rollbacks, self.budget.max_rollbacks)
            || Self::at_or_over(
                self.consecutive_failures,
                self.budget.max_consecutive_failures,
            )
            || Self::at_or_over(self.recent.len() as u32, self.budget.max_window_failures)
    }

    fn at_or_over(observed: u32, limit: u32) -> bool {
        observed > 0 && observed >= limit
    }

    pub fn save(&self, path: &Path) -> CrateResult<()> {
        self.validate()
            .map_err(|error| CrateError::Invalid(error.to_string()))?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(self)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> CrateResult<Self> {
        let bytes = fs::read(path)?;
        let tracker: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&tracker)? != bytes {
            return Err(CrateError::Journal(
                "failure tracker bytes are not canonical JSON".into(),
            ));
        }
        tracker
            .validate()
            .map_err(|error| CrateError::Invalid(error.to_string()))?;
        Ok(tracker)
    }

    pub fn recover(path: &Path) -> CrateResult<Self> {
        match Self::load(path) {
            Ok(tracker) => Ok(tracker),
            Err(CrateError::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let tracker = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(tracker)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_lattice_has_explicit_bottom_top_and_no_implicit_edges() {
        let bottom = CapabilitySet::empty();
        let read = CapabilitySet::from_slice(&[Authority::Read]);
        let write = CapabilitySet::from_slice(&[Authority::Write]);
        let top = CapabilitySet::all();

        assert!(bottom.leq(&read));
        assert!(read.leq(&top));
        assert!(top.covers(&read));
        assert!(!write.covers(&read));
        assert!(!read.covers(&write));
        assert_eq!(read.join(&write).len(), 2);
        assert!(read.meet(&write).is_empty());
    }

    #[test]
    fn lifecycle_accepts_only_declared_order() {
        let mut lifecycle = Lifecycle::new();
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Admit).unwrap(),
            LifecycleState::Admitted
        );
        assert_eq!(
            lifecycle.apply(LifecycleEvent::BeginExecution).unwrap(),
            LifecycleState::Executing
        );
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Complete).unwrap(),
            LifecycleState::Completed
        );
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Rollback).unwrap(),
            LifecycleState::RolledBack
        );
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Admit).unwrap(),
            LifecycleState::Admitted
        );
        assert_eq!(lifecycle.revision, 5);

        let before = lifecycle.clone();
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Complete),
            Err(ContractError::InvalidTransition {
                state: LifecycleState::Admitted,
                event: LifecycleEvent::Complete,
            })
        );
        assert_eq!(lifecycle, before);
    }

    #[test]
    fn freeze_and_kill_are_one_way_controls() {
        let mut lifecycle = Lifecycle::new();
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Freeze).unwrap(),
            LifecycleState::Frozen
        );
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Admit),
            Err(ContractError::InvalidTransition {
                state: LifecycleState::Frozen,
                event: LifecycleEvent::Admit,
            })
        );
        assert_eq!(
            lifecycle.apply(LifecycleEvent::Kill).unwrap(),
            LifecycleState::Killed
        );
        assert_eq!(lifecycle.state, LifecycleState::Killed);
    }

    #[test]
    fn failure_budget_validates_and_freezes_at_inclusive_limit() {
        let budget = FailureBudget {
            max_rejections: 2,
            max_quarantines: 3,
            max_rollbacks: 3,
            max_consecutive_failures: 2,
            max_window_failures: 3,
            window_size: 4,
        };
        let mut tracker = budget.tracker().unwrap();
        assert_eq!(
            tracker.record_failure(FailureKind::Rejection).unwrap(),
            BudgetDecision::Continue
        );
        assert_eq!(
            tracker.record_failure(FailureKind::Rollback).unwrap(),
            BudgetDecision::FreezeRequired
        );
        assert!(tracker.is_exhausted());
        assert_eq!(
            tracker.record_failure(FailureKind::Quarantine),
            Err(ContractError::BudgetExhausted)
        );
    }

    #[test]
    fn failure_budget_rejects_invalid_window() {
        let budget = FailureBudget {
            max_rejections: 1,
            max_quarantines: 1,
            max_rollbacks: 1,
            max_consecutive_failures: 1,
            max_window_failures: 2,
            window_size: 1,
        };
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidBudget(_))
        ));
    }

    #[test]
    fn zero_budget_freezes_on_first_observation() {
        let budget = FailureBudget {
            max_rejections: 0,
            max_quarantines: 1,
            max_rollbacks: 1,
            max_consecutive_failures: 1,
            max_window_failures: 1,
            window_size: 1,
        };
        let mut tracker = budget.tracker().unwrap();
        assert!(!tracker.is_exhausted());
        assert_eq!(
            tracker.record_failure(FailureKind::Rejection).unwrap(),
            BudgetDecision::FreezeRequired
        );
    }

    #[test]
    fn failure_tracker_snapshot_is_canonical_and_recoverable() {
        let budget = FailureBudget {
            max_rejections: 3,
            max_quarantines: 3,
            max_rollbacks: 3,
            max_consecutive_failures: 3,
            max_window_failures: 3,
            window_size: 4,
        };
        let mut tracker = budget.tracker().expect("tracker");
        tracker
            .record_failure(FailureKind::Rejection)
            .expect("record");
        tracker.validate().expect("validate");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("failures.json");
        tracker.save(&path).expect("save");
        assert_eq!(FailureTracker::load(&path).expect("load"), tracker);
        let canonical = std::fs::read(&path).expect("canonical");
        let mut tampered = canonical.clone();
        let tamper_index = tampered.len() - 2;
        tampered[tamper_index] = b' ';
        std::fs::write(&path, tampered).expect("tamper");
        assert!(FailureTracker::load(&path).is_err());
        std::fs::write(path.with_extension("tmp"), canonical).expect("temporary");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(FailureTracker::recover(&path).expect("recover"), tracker);
    }

    #[test]
    fn failure_tracker_rejects_inconsistent_persisted_counters() {
        let budget = FailureBudget {
            max_rejections: 3,
            max_quarantines: 3,
            max_rollbacks: 3,
            max_consecutive_failures: 3,
            max_window_failures: 3,
            window_size: 4,
        };
        let mut tracker = budget.tracker().expect("tracker");
        tracker.consecutive_failures = 1;
        assert!(tracker.validate().is_err());
    }
}
