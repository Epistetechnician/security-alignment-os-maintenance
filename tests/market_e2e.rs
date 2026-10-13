//! Public end-to-end coverage for the fixed local compute receipt seam.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::checker;
use security_alignment_os::market::{
    execute_local, execute_local_with_offer, select_offer, ReceiptVerifier, SettlementStatus,
    SumJob, SumOffer,
};
use security_alignment_os::Error;

#[test]
fn selected_offer_flows_through_receipt_verification_and_authorization_gate() {
    let job = SumJob::new("sum-e2e".into(), "requester".into(), vec![4, 5, 6], 100, 10)
        .expect("fixed sum job");
    let offers = [
        SumOffer::new(&job, "offer-a".into(), "provider-a".into(), 5, 10, 90)
            .expect("first synthetic offer"),
        SumOffer::new(&job, "offer-b".into(), "provider-b".into(), 3, 10, 90)
            .expect("second synthetic offer"),
    ];
    let selected = select_offer(&job, &offers, 20).expect("deterministic offer selection");
    assert_eq!(selected.offer_id, "offer-b");

    let receipt = execute_local_with_offer(&job, selected, 20).expect("fixed local execution");
    assert_eq!(receipt.output, 15);
    assert_eq!(receipt.provider, selected.provider);
    assert_eq!(receipt.price, selected.price);
    checker::validate_receipt(&job, &receipt, 20).expect("independent receipt recomputation");

    let mut verifier = ReceiptVerifier::default();
    assert!(verifier.verify(&job, &receipt, 20).expect("verify receipt"));
    assert!(!verifier
        .verify(&job, &receipt, 20)
        .expect("reject receipt replay"));

    let wrong_offer = &offers[0];
    assert!(verifier
        .propose_settlement_for_offer(&job, wrong_offer, &receipt, 20)
        .is_err());
    let settlement = verifier
        .propose_settlement_for_offer(&job, selected, &receipt, 20)
        .expect("propose settlement after verification");
    assert_eq!(settlement.offer_id, selected.offer_id);
    assert_eq!(settlement.provider, selected.provider);
    assert_eq!(settlement.price, selected.price);
    assert_eq!(settlement.status, SettlementStatus::AuthorizationRequired);
    settlement
        .validate(&job, &receipt)
        .expect("validate authorization-required proposal");

    let directory = tempfile::tempdir().expect("temporary verifier custody");
    let path = directory.path().join("market-verifier.json");
    verifier
        .save(&path)
        .expect("persist local verification state");
    let mut recovered = ReceiptVerifier::recover(&path).expect("recover local verification state");
    assert!(
        recovered
            .propose_settlement_for_offer(&job, selected, &receipt, 20)
            .is_err(),
        "persisted reservation must prevent duplicate settlement proposals"
    );
}

#[test]
fn invalid_receipts_offers_and_overflow_never_reach_authorization() {
    let job = SumJob::new(
        "sum-negative".into(),
        "requester".into(),
        vec![4, 5],
        100,
        10,
    )
    .expect("fixed sum job");
    let offer =
        SumOffer::new(&job, "offer".into(), "provider".into(), 3, 10, 90).expect("synthetic offer");
    let mut receipt = execute_local_with_offer(&job, &offer, 20).expect("local offer execution");
    let mut verifier = ReceiptVerifier::default();

    receipt.output += 1;
    assert!(!verifier
        .verify(&job, &receipt, 20)
        .expect("reject forged output"));
    assert!(verifier
        .propose_settlement_for_offer(&job, &offer, &receipt, 20)
        .is_err());

    let mut tampered_offer = offer.clone();
    tampered_offer.price = job.max_price + 1;
    assert!(select_offer(&job, &[tampered_offer], 20).is_err());

    assert!(matches!(
        SumJob::new(
            "overflow".into(),
            "requester".into(),
            vec![u64::MAX, 1],
            100,
            0
        ),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn cross_job_offer_cannot_be_silently_ignored_when_a_valid_offer_exists() {
    let job = SumJob::new(
        "sum-bound-job".into(),
        "requester".into(),
        vec![2, 3],
        100,
        10,
    )
    .expect("fixed sum job");
    let foreign_job = SumJob::new(
        "sum-foreign-job".into(),
        "requester".into(),
        vec![4, 5],
        100,
        10,
    )
    .expect("foreign fixed sum job");
    let valid_offer = SumOffer::new(&job, "offer-valid".into(), "provider-a".into(), 3, 10, 90)
        .expect("valid offer");
    let foreign_offer = SumOffer::new(
        &foreign_job,
        "offer-foreign".into(),
        "provider-b".into(),
        2,
        10,
        90,
    )
    .expect("foreign offer is internally valid for its own job");

    assert!(matches!(
        select_offer(&job, &[valid_offer, foreign_offer], 20),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn offer_receipt_must_complete_in_window_but_settlement_can_follow_expiry() {
    let job = SumJob::new(
        "sum-offer-window".into(),
        "requester".into(),
        vec![3, 4],
        100,
        10,
    )
    .expect("fixed sum job");
    let offer = SumOffer::new(&job, "offer-window".into(), "provider-a".into(), 5, 10, 30)
        .expect("bounded offer");
    let receipt = execute_local_with_offer(&job, &offer, 20).expect("in-window receipt");
    let mut verifier = ReceiptVerifier::default();

    let mut completed_before_offer = receipt.clone();
    completed_before_offer.completed_at = offer.submitted_at - 1;
    assert!(verifier
        .verify(&job, &completed_before_offer, 40)
        .expect("generic receipt bindings validate"));
    assert!(verifier
        .propose_settlement_for_offer(&job, &offer, &completed_before_offer, 40)
        .is_err());

    let mut completed_after_expiry = receipt.clone();
    completed_after_expiry.completed_at = offer.expires_at;
    assert!(verifier
        .verify(&job, &completed_after_expiry, 40)
        .expect("generic receipt bindings validate"));
    assert!(verifier
        .propose_settlement_for_offer(&job, &offer, &completed_after_expiry, 40)
        .is_err());

    assert!(verifier
        .verify(&job, &receipt, 40)
        .expect("verify in-window receipt"));
    let settlement = verifier
        .propose_settlement_for_offer(&job, &offer, &receipt, 40)
        .expect("valid completed work can be proposed before the job deadline");
    settlement
        .validate(&job, &receipt)
        .expect("authorization-required proposal remains bound");
}

#[test]
fn direct_local_receipt_is_zero_price_and_expires_at_the_job_deadline() {
    let job = SumJob::new("sum-direct".into(), "requester".into(), vec![7], 30, 5)
        .expect("fixed sum job");
    let receipt = execute_local(&job, 29).expect("local direct execution");
    assert_eq!(receipt.price, 0);
    assert_eq!(receipt.output, 7);

    let mut verifier = ReceiptVerifier::default();
    assert!(verifier
        .verify(&job, &receipt, 29)
        .expect("verify local receipt"));
    assert!(execute_local(&job, 30).is_err());
    assert!(!verifier
        .verify(&job, &receipt, 30)
        .expect("expired receipt rejected"));
}
