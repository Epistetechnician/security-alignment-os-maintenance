//! Proposal-only adaptation planning and deterministic local work-market selection.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module is an exploratory seam above the reviewed broker. It can rank
//! bounded proposals and local work offers, but it cannot mutate a checkout,
//! authorize execution, promote a candidate, or settle a price. Inconclusive
//! evidence produces `NoCandidate` rather than a proxy acceptance.

use crate::governance::{CandidateUpdate, ReleaseRegistry};
use crate::{digest, valid_digest, Error, Result, CLAIM_CEILING};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ADAPTATION_VERSION: u8 = 1;
pub const EXPLORATORY_CLAIM_CEILING: &str = CLAIM_CEILING;

const MAX_ID_LEN: usize = 128;

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID_LEN && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EvidenceStatus {
    LocalOnly,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceAnchor {
    pub evidence_digest: String,
    pub source_digest: String,
    pub base_digest: String,
    pub claim_ceiling: String,
    pub status: EvidenceStatus,
    pub observed_at: u64,
    pub valid_until: u64,
}

impl EvidenceAnchor {
    pub fn validate(&self) -> Result<()> {
        if !valid_digest(&self.evidence_digest)
            || !valid_digest(&self.source_digest)
            || !valid_digest(&self.base_digest)
            || self.claim_ceiling != EXPLORATORY_CLAIM_CEILING
            || self.valid_until <= self.observed_at
            || self.observed_at == 0
        {
            return Err(Error::Invalid(
                "adaptation evidence anchor is malformed".into(),
            ));
        }
        Ok(())
    }

    pub fn usable_at(&self, now: u64) -> bool {
        self.validate().is_ok()
            && self.status == EvidenceStatus::LocalOnly
            && now >= self.observed_at
            && now < self.valid_until
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdaptationCandidate {
    pub candidate: CandidateUpdate,
    pub evidence: EvidenceAnchor,
    pub priority: u64,
    pub execution_authorized: bool,
}

impl AdaptationCandidate {
    pub fn validate(&self) -> Result<()> {
        self.candidate.validate()?;
        self.evidence.validate()?;
        if self.candidate.base_digest != self.evidence.base_digest
            || self.candidate.evidence_digest != self.evidence.evidence_digest
            || self.execution_authorized
        {
            return Err(Error::Rejected(
                "adaptation candidate is not bound to its immutable local evidence".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdaptationPlan {
    pub version: u8,
    pub plan_id: String,
    pub candidate_digest: String,
    pub base_digest: String,
    pub rollback_digest: String,
    pub evidence_digest: String,
    pub source_digest: String,
    pub claim_ceiling: String,
    pub valid_until: u64,
    pub execution_authorized: bool,
}

impl AdaptationPlan {
    fn from_candidate(candidate: &AdaptationCandidate) -> Result<Self> {
        let candidate_digest = candidate.digest()?;
        let plan = Self {
            version: ADAPTATION_VERSION,
            plan_id: digest(&("adaptation-plan-v1", &candidate_digest))?,
            candidate_digest,
            base_digest: candidate.candidate.base_digest.clone(),
            rollback_digest: candidate.candidate.rollback_digest.clone(),
            evidence_digest: candidate.evidence.evidence_digest.clone(),
            source_digest: candidate.evidence.source_digest.clone(),
            claim_ceiling: EXPLORATORY_CLAIM_CEILING.into(),
            valid_until: candidate.evidence.valid_until,
            execution_authorized: false,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != ADAPTATION_VERSION
            || !valid_id(&self.plan_id)
            || !valid_digest(&self.candidate_digest)
            || !valid_digest(&self.base_digest)
            || !valid_digest(&self.rollback_digest)
            || !valid_digest(&self.evidence_digest)
            || !valid_digest(&self.source_digest)
            || self.claim_ceiling != EXPLORATORY_CLAIM_CEILING
            || self.valid_until == 0
            || self.base_digest != self.rollback_digest
            || self.execution_authorized
            || self.plan_id != digest(&("adaptation-plan-v1", &self.candidate_digest))?
        {
            return Err(Error::Rejected("adaptation plan is malformed".into()));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }

    /// Records the bound candidate in governance shadow state only.
    pub fn stage_shadow(
        &self,
        candidate: &AdaptationCandidate,
        registry: &mut ReleaseRegistry,
    ) -> Result<()> {
        self.validate()?;
        candidate.validate()?;
        if candidate.digest()? != self.candidate_digest {
            return Err(Error::Rejected(
                "shadow candidate does not match adaptation plan".into(),
            ));
        }
        registry.propose(candidate.candidate.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkOffer {
    pub plan_digest: String,
    pub offer_id: String,
    pub provider: String,
    pub price: u64,
    pub submitted_at: u64,
    pub expires_at: u64,
}

impl WorkOffer {
    pub fn validate(&self, plan: &AdaptationPlan, now: u64) -> Result<()> {
        plan.validate()?;
        if !valid_digest(&self.plan_digest)
            || self.plan_digest != plan.digest()?
            || !valid_id(&self.offer_id)
            || !valid_id(&self.provider)
            || self.submitted_at == 0
            || self.submitted_at > now
            || self.expires_at <= self.submitted_at
            || self.expires_at > plan.valid_until
        {
            return Err(Error::Rejected("adaptation work offer is malformed".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanDisposition {
    Candidate(AdaptationPlan),
    NoCandidate(&'static str),
}

/// Selects one proposal from local, still-valid evidence without authorizing it.
pub fn select_plan(candidates: &[AdaptationCandidate], now: u64) -> Result<PlanDisposition> {
    if candidates.is_empty() {
        return Ok(PlanDisposition::NoCandidate(
            "no adaptation proposals supplied",
        ));
    }
    for candidate in candidates {
        candidate.validate()?;
    }
    let mut eligible = candidates
        .iter()
        .filter(|candidate| candidate.evidence.usable_at(now))
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Ok(PlanDisposition::NoCandidate(
            "evidence is inconclusive or expired",
        ));
    }
    eligible.sort_by(|left, right| {
        (
            right.priority,
            &left.candidate.base_digest,
            &left.candidate.candidate_digest,
        )
            .cmp(&(
                left.priority,
                &right.candidate.base_digest,
                &right.candidate.candidate_digest,
            ))
    });
    AdaptationPlan::from_candidate(eligible[0]).map(PlanDisposition::Candidate)
}

/// Selects the cheapest unexpired offer with deterministic tie-breaking.
pub fn select_work_offer<'a>(
    plan: &AdaptationPlan,
    offers: &'a [WorkOffer],
    now: u64,
) -> Result<&'a WorkOffer> {
    let mut eligible = Vec::new();
    let mut offer_ids = BTreeSet::new();
    for offer in offers {
        offer.validate(plan, now)?;
        if now < offer.expires_at {
            if !offer_ids.insert(offer.offer_id.clone()) {
                return Err(Error::Quarantined(
                    "duplicate eligible adaptation offer identity".into(),
                ));
            }
            eligible.push(offer);
        }
    }
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
        .ok_or_else(|| Error::Quarantined("no eligible adaptation work offer".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(priority: u64, status: EvidenceStatus) -> AdaptationCandidate {
        let base = "a".repeat(64);
        let evidence = "b".repeat(64);
        AdaptationCandidate {
            candidate: CandidateUpdate {
                candidate_id: format!("candidate-{priority}"),
                base_digest: base.clone(),
                candidate_digest: "c".repeat(64),
                rollback_digest: base.clone(),
                evidence_digest: evidence.clone(),
            },
            evidence: EvidenceAnchor {
                evidence_digest: evidence,
                source_digest: "d".repeat(64),
                base_digest: base,
                claim_ceiling: EXPLORATORY_CLAIM_CEILING.into(),
                status,
                observed_at: 1,
                valid_until: 100,
            },
            priority,
            execution_authorized: false,
        }
    }

    fn offer(plan: &AdaptationPlan, id: &str, provider: &str, price: u64) -> WorkOffer {
        WorkOffer {
            plan_digest: plan.digest().expect("plan digest"),
            offer_id: id.into(),
            provider: provider.into(),
            price,
            submitted_at: 10,
            expires_at: 90,
        }
    }

    #[test]
    fn local_evidence_selects_deterministic_proposal_without_authority() {
        let low = candidate(1, EvidenceStatus::LocalOnly);
        let high = candidate(2, EvidenceStatus::LocalOnly);
        let first = select_plan(&[low.clone(), high.clone()], 10).expect("plan");
        let second = select_plan(&[low, high], 10).expect("plan replay");
        assert_eq!(first, second);
        let PlanDisposition::Candidate(plan) = first else {
            panic!("expected candidate");
        };
        assert!(!plan.execution_authorized);
        assert_eq!(plan.base_digest, plan.rollback_digest);
    }

    #[test]
    fn inconclusive_or_expired_evidence_returns_no_candidate() {
        assert_eq!(
            select_plan(&[candidate(1, EvidenceStatus::Inconclusive)], 10).unwrap(),
            PlanDisposition::NoCandidate("evidence is inconclusive or expired")
        );
        assert_eq!(
            select_plan(&[candidate(1, EvidenceStatus::LocalOnly)], 100).unwrap(),
            PlanDisposition::NoCandidate("evidence is inconclusive or expired")
        );
    }

    #[test]
    fn mismatched_base_or_execution_authority_is_rejected() {
        let mut mismatched = candidate(1, EvidenceStatus::LocalOnly);
        mismatched.candidate.base_digest = "e".repeat(64);
        assert!(select_plan(&[mismatched], 10).is_err());

        let mut authorized = candidate(1, EvidenceStatus::LocalOnly);
        authorized.execution_authorized = true;
        assert!(select_plan(&[authorized], 10).is_err());
    }

    #[test]
    fn work_market_tie_breaks_are_deterministic_and_duplicates_quarantine() {
        let PlanDisposition::Candidate(plan) =
            select_plan(&[candidate(1, EvidenceStatus::LocalOnly)], 10).unwrap()
        else {
            panic!("expected candidate");
        };
        let offers = [
            offer(&plan, "offer-b", "provider-b", 4),
            offer(&plan, "offer-a", "provider-a", 4),
            offer(&plan, "offer-c", "provider-c", 5),
        ];
        assert_eq!(select_work_offer(&plan, &offers, 20).unwrap(), &offers[1]);

        let duplicate = [
            offer(&plan, "same", "provider-a", 1),
            offer(&plan, "same", "provider-b", 2),
        ];
        assert!(matches!(
            select_work_offer(&plan, &duplicate, 20),
            Err(Error::Quarantined(_))
        ));
    }

    #[test]
    fn expired_offer_is_not_selected() {
        let PlanDisposition::Candidate(plan) =
            select_plan(&[candidate(1, EvidenceStatus::LocalOnly)], 10).unwrap()
        else {
            panic!("expected candidate");
        };
        let mut expired = offer(&plan, "expired", "provider", 1);
        expired.expires_at = 20;
        assert!(select_work_offer(&plan, &[expired], 20).is_err());
    }
}
