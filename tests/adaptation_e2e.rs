//! Public end-to-end coverage for the proposal-only adaptation seam.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::adaptation::{
    select_plan, select_work_offer, AdaptationCandidate, EvidenceAnchor, EvidenceStatus,
    PlanDisposition, WorkOffer, EXPLORATORY_CLAIM_CEILING,
};
use security_alignment_os::governance::{CandidateUpdate, ReleaseRegistry, ReleaseState};

fn candidate() -> AdaptationCandidate {
    let base = "a".repeat(64);
    let evidence = "b".repeat(64);
    AdaptationCandidate {
        candidate: CandidateUpdate {
            candidate_id: "candidate-e2e".into(),
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
            status: EvidenceStatus::LocalOnly,
            observed_at: 1,
            valid_until: 100,
        },
        priority: 10,
        execution_authorized: false,
    }
}

#[test]
fn proposal_offer_shadow_flow_stays_non_authoritative() {
    let proposal = candidate();
    let PlanDisposition::Candidate(plan) =
        select_plan(std::slice::from_ref(&proposal), 10).expect("select proposal")
    else {
        panic!("expected proposal");
    };
    let offer = WorkOffer {
        plan_digest: plan.digest().expect("plan digest"),
        offer_id: "offer-e2e".into(),
        provider: "provider-e2e".into(),
        price: 3,
        submitted_at: 10,
        expires_at: 90,
    };
    assert_eq!(
        select_work_offer(&plan, &[offer], 20)
            .expect("select offer")
            .offer_id,
        "offer-e2e"
    );

    let mut registry = ReleaseRegistry::default();
    plan.stage_shadow(&proposal, &mut registry)
        .expect("stage shadow");
    assert_eq!(registry.state("candidate-e2e"), Some(ReleaseState::Shadow));
    assert!(
        !plan.execution_authorized,
        "planning must not authorize execution"
    );
}

#[test]
fn shadow_staging_rejects_a_different_candidate() {
    let proposal = candidate();
    let PlanDisposition::Candidate(plan) =
        select_plan(std::slice::from_ref(&proposal), 10).expect("select proposal")
    else {
        panic!("expected proposal");
    };
    let mut different = candidate();
    different.candidate.candidate_id = "different".into();
    let mut registry = ReleaseRegistry::default();
    assert!(plan.stage_shadow(&different, &mut registry).is_err());
    assert_eq!(registry.state("candidate-e2e"), None);
}
