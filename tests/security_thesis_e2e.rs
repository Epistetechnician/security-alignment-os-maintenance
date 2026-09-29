//! Public, deterministic end-to-end assay for the foundation control thesis.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::claims::{AggregateReleasePacket, ClaimEnvelope};
use security_alignment_os::contract::LifecycleState;
use security_alignment_os::custody::{CustodyRegistry, CustodyRoot, LocalCustodyPaths};
use security_alignment_os::execution_gate::{
    ExecutionGate, ExternalExecutionRequest, GateDisposition, SandboxAttestation,
};
use security_alignment_os::integration::{
    self, Disposition, EvidenceBinding, Observation, ReceiptBinding,
};
use security_alignment_os::receipts::{ReceiptSigner, ReceiptVerifier};
use security_alignment_os::{
    artifacts::{ArtifactManifest, ArtifactRegistry},
    audit::AuditJournal,
    checker, digest, digest_bytes, Action, Claim, Evidence, EvidenceRegistry, Kernel, Policy,
    Proposal, Runtime, CLAIM_CEILING, STATE_SLICE,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn proposal(candidate_id: &str, nonce: u64) -> Proposal {
    Proposal {
        candidate_id: candidate_id.into(),
        agent_id: "synthetic-agent".into(),
        intent: "write one value inside the declared local scope".into(),
        action: Action::Write,
        scope: "sandbox".into(),
        payload: BTreeMap::from([
            ("key".into(), Value::String("sandbox:answer".into())),
            ("value".into(), Value::String("bounded".into())),
        ]),
        resource_cost: BTreeMap::from([
            ("cpu_ms".into(), 1),
            ("bytes".into(), 7),
            ("spend".into(), 0),
        ]),
        source_digest: "a".repeat(64),
        claims: vec![Claim {
            guarantees: vec!["PolicyCompliance".into()],
            assumptions: Vec::new(),
            excludes: vec!["scientific_alignment".into()],
            maturity: 1,
            trust_roots: vec!["synthetic-local-fixture".into()],
            valid_until: 1_000,
            provenance_digest: "b".repeat(64),
        }],
        nonce,
        expires_at: 500,
        requests_direct_authority: false,
    }
}

fn accepted_evidence(proposal: &Proposal, id: &str) -> EvidenceRegistry {
    let mut registry = EvidenceRegistry::default();
    registry
        .insert(Evidence {
            id: id.into(),
            source_digest: proposal.digest().expect("proposal digest"),
            operator_id: "synthetic-operator".into(),
            validator_id: "synthetic-validator".into(),
            reviewer_id: "synthetic-reviewer".into(),
            valid_until: 1_000,
            accepted: true,
            revoked: false,
        })
        .expect("insert accepted synthetic evidence");
    registry
}

fn accepted_artifact(artifact_id: &str, subject_digest: &str) -> ArtifactRegistry {
    let mut artifacts = ArtifactRegistry::default();
    artifacts
        .quarantine(
            ArtifactManifest {
                artifact_id: artifact_id.into(),
                subject_digest: subject_digest.into(),
                source_digest: "3".repeat(64),
                license: "MIT synthetic fixture".into(),
                provenance_digest: "4".repeat(64),
                custody_root: "synthetic-root".into(),
                retention_start: 0,
                retention_until: 100,
            },
            "synthetic-operator",
            "synthetic-validator",
        )
        .expect("quarantine source artifact");
    artifacts
        .accept(artifact_id, subject_digest, "synthetic-reviewer", 10)
        .expect("accept source artifact fixture");
    artifacts
}

fn accepted_custody(
    custody_id: &str,
    root_id: &str,
    artifact_digest: &str,
    retention_until: u64,
) -> CustodyRegistry {
    let mut custody = CustodyRegistry::default();
    custody
        .declare(
            custody_id,
            CustodyRoot {
                root_id: root_id.into(),
                owner_id: "synthetic-owner".into(),
                root_digest: "5".repeat(64),
                mode: 0o700,
                external_to_repository: true,
                created_at: 0,
                expires_at: 1_000,
                raw_retention_until: retention_until,
            },
            artifact_digest,
            "synthetic-owner",
            "synthetic-validator",
        )
        .expect("declare synthetic custody");
    custody
}

fn signed_receipt(
    proposal: &Proposal,
) -> (
    Policy,
    ReceiptSigner,
    security_alignment_os::receipts::CapabilityReceipt,
) {
    let policy = Policy::default();
    let mut issuer_kernel = Kernel::new(policy.clone()).expect("issuer kernel");
    let decision = issuer_kernel.admit(proposal, 10).expect("issuer admission");
    let signer = ReceiptSigner::from_seed("synthetic-test-issuer", [17; 32]).expect("test signer");
    let receipt = signer
        .issue("synthetic-tenant", proposal, &decision, &policy)
        .expect("signed local receipt");
    (policy, signer, receipt)
}

fn observation(healthy: bool) -> Observation {
    Observation {
        at: 10,
        healthy,
        telemetry_present: true,
        kill_requested: false,
    }
}

#[test]
fn accepted_subject_bound_receipt_completes_once_and_persists_auditable_state() {
    let proposal = proposal("e2e-completion", 1);
    let evidence = accepted_evidence(&proposal, "e2e-evidence");
    let (policy, signer, receipt) = signed_receipt(&proposal);
    let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
        .expect("receipt verifier");
    let mut kernel = Kernel::new(policy).expect("runtime kernel");
    let mut runtime = Runtime::default();

    let result = integration::run_with_receipt(
        &mut kernel,
        &mut runtime,
        &evidence,
        "e2e-evidence",
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        &proposal,
        observation(true),
    )
    .expect("complete workflow");

    assert_eq!(result.disposition, Disposition::Completed);
    assert_eq!(result.subject_digest, proposal.digest().expect("subject"));
    assert_eq!(
        runtime.state.get("sandbox:answer"),
        Some(&Value::String("bounded".into()))
    );
    assert_eq!(
        kernel.lifecycle_state(&result.subject_digest),
        Some(LifecycleState::Completed)
    );
    checker::validate_replay(&kernel.journal).expect("replay journal");
    checker::validate_lifecycles(&kernel.journal, &kernel.lifecycle_records())
        .expect("lifecycle records");
    let audit = runtime.audit_journal().expect("audit journal");
    checker::validate_audit(&audit).expect("independent local audit recomputation");

    let directory = tempfile::tempdir().expect("temporary custody directory");
    let audit_path = directory.path().join("audit.json");
    runtime.save_audit(&audit_path).expect("persist audit");
    assert_eq!(
        AuditJournal::load(&audit_path).expect("reload audit"),
        audit
    );

    let before_replay = runtime.snapshot();
    let replay = integration::run_with_receipt(
        &mut kernel,
        &mut runtime,
        &evidence,
        "e2e-evidence",
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        &proposal,
        observation(true),
    );
    assert!(
        replay.is_err(),
        "a completed proposal must not be replayable"
    );
    assert_eq!(
        runtime.snapshot(),
        before_replay,
        "replay changed runtime state"
    );
}

#[test]
fn missing_evidence_quarantines_before_admission_or_mutation() {
    let proposal = proposal("e2e-missing-evidence", 5);
    let mut kernel = Kernel::new(Policy::default()).expect("kernel");
    let mut runtime = Runtime::default();
    let evidence = EvidenceRegistry::default();

    let result = integration::run(
        &mut kernel,
        &mut runtime,
        &evidence,
        "missing-evidence",
        &proposal,
        observation(true),
    )
    .expect("missing evidence quarantine");

    assert_eq!(result.disposition, Disposition::Quarantined);
    assert!(result.decision_digest.is_none());
    assert!(kernel.journal.entries.is_empty());
    assert!(runtime.state.is_empty());
    assert!(runtime.audit.is_empty());
}

#[test]
fn unhealthy_observation_rolls_back_then_freezes_the_workflow() {
    let proposal = proposal("e2e-rollback", 2);
    let evidence = accepted_evidence(&proposal, "rollback-evidence");
    let (policy, signer, receipt) = signed_receipt(&proposal);
    let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
        .expect("receipt verifier");
    let mut kernel = Kernel::new(policy).expect("runtime kernel");
    let mut runtime = Runtime::default();
    runtime
        .state
        .insert("sandbox:prior".into(), Value::String("preserved".into()));

    let result = integration::run_with_receipt(
        &mut kernel,
        &mut runtime,
        &evidence,
        "rollback-evidence",
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        &proposal,
        observation(false),
    )
    .expect("rollback workflow");

    assert_eq!(result.disposition, Disposition::RolledBack);
    assert_eq!(runtime.state.len(), 1);
    assert_eq!(
        runtime.state.get("sandbox:prior"),
        Some(&Value::String("preserved".into()))
    );
    assert!(!runtime.state.contains_key("sandbox:answer"));
    assert!(runtime.is_frozen());
    assert_eq!(
        kernel.lifecycle_state(&result.subject_digest),
        Some(LifecycleState::Frozen)
    );
    checker::validate_audit(&runtime.audit_journal().expect("audit"))
        .expect("rollback audit chain");
}

#[test]
fn receipt_subject_substitution_quarantines_before_mutation() {
    let proposal = proposal("e2e-wrong-subject", 3);
    let evidence = accepted_evidence(&proposal, "wrong-subject-evidence");
    let (policy, signer, receipt) = signed_receipt(&proposal);
    let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
        .expect("receipt verifier");
    let mut kernel = Kernel::new(policy).expect("runtime kernel");
    let mut runtime = Runtime::default();

    let result = integration::run_with_receipt(
        &mut kernel,
        &mut runtime,
        &evidence,
        "wrong-subject-evidence",
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "different-tenant",
        },
        &proposal,
        observation(true),
    )
    .expect("quarantine disposition");

    assert_eq!(result.disposition, Disposition::Quarantined);
    assert!(runtime.state.is_empty());
    assert!(runtime.audit.is_empty());
    assert_eq!(
        kernel.lifecycle_state(&result.subject_digest),
        Some(LifecycleState::Quarantined)
    );
}

#[test]
fn invalid_receipt_signature_quarantines_before_mutation() {
    let proposal = proposal("e2e-forged-receipt", 6);
    let evidence = accepted_evidence(&proposal, "forged-receipt-evidence");
    let (policy, signer, receipt) = signed_receipt(&proposal);
    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
        .expect("receipt verifier");
    let mut kernel = Kernel::new(policy).expect("runtime kernel");
    let mut runtime = Runtime::default();

    let result = integration::run_with_receipt(
        &mut kernel,
        &mut runtime,
        &evidence,
        "forged-receipt-evidence",
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &forged,
            subject: "synthetic-tenant",
        },
        &proposal,
        observation(true),
    )
    .expect("forged receipt quarantine");

    assert_eq!(result.disposition, Disposition::Quarantined);
    assert!(runtime.state.is_empty());
    assert!(runtime.audit.is_empty());
    assert_eq!(
        kernel.lifecycle_state(&result.subject_digest),
        Some(LifecycleState::Quarantined)
    );
}

#[test]
fn claim_meet_cannot_expand_scope_and_external_execution_stays_blocked() {
    let first = ClaimEnvelope {
        claim_id: "local-control".into(),
        state_slice: STATE_SLICE.into(),
        claim_ceiling: CLAIM_CEILING.into(),
        guarantees: BTreeSet::from(["PolicyCompliance".into(), "BoundedMutation".into()]),
        assumptions: BTreeSet::from(["caller_owned_storage".into()]),
        excludes: BTreeSet::from(["scientific_alignment".into()]),
        evidence_digests: BTreeSet::from(["c".repeat(64)]),
        valid_until: 100,
    };
    let second = ClaimEnvelope {
        claim_id: "local-audit".into(),
        state_slice: STATE_SLICE.into(),
        claim_ceiling: CLAIM_CEILING.into(),
        guarantees: BTreeSet::from(["PolicyCompliance".into()]),
        assumptions: BTreeSet::from(["local_rust_runtime".into()]),
        excludes: BTreeSet::from(["production_security".into()]),
        evidence_digests: BTreeSet::from(["d".repeat(64)]),
        valid_until: 80,
    };
    let met = first.meet(&second).expect("meet-only claim composition");
    assert_eq!(met.guarantees, BTreeSet::from(["PolicyCompliance".into()]));
    assert_eq!(met.valid_until, 80);
    assert!(met.excludes.contains("scientific_alignment"));
    assert!(met.excludes.contains("production_security"));
    let packet =
        AggregateReleasePacket::from_envelopes("local-e2e", &[met], 20).expect("aggregate packet");
    assert!(!packet.raw_payload_included);
    assert_eq!(packet.state_slice, STATE_SLICE);
    assert_eq!(packet.claim_ceiling, CLAIM_CEILING);

    let decision = ExecutionGate::new()
        .authorize(
            &SandboxAttestation {
                attestation_id: "synthetic-attestation".into(),
                executor_digest: "e".repeat(64),
                egress_denied: true,
                secret_broker: true,
                independent_kill_path: true,
                memory_bytes: 1,
                cpu_ms: 1,
                issued_at: 0,
                expires_at: 100,
            },
            &ExternalExecutionRequest {
                request_id: "synthetic-request".into(),
                program_digest: "f".repeat(64),
                input_digest: "1".repeat(64),
                output_schema_digest: "2".repeat(64),
                proof_system: "local-fixture".into(),
                privacy_requirement: "local-only".into(),
                requested_at: 0,
                deadline: 100,
                max_price: 0,
            },
            10,
        )
        .expect("valid synthetic request is still closed");
    assert_eq!(decision.disposition, GateDisposition::Blocked);
}

#[test]
fn artifact_binding_is_required_before_the_proposal_workflow() {
    let proposal = proposal("e2e-artifact", 4);
    let evidence = accepted_evidence(&proposal, "artifact-evidence");
    let artifacts = accepted_artifact("synthetic-source", &proposal.source_digest);
    let custody = accepted_custody(
        "source-custody",
        "synthetic-root",
        &proposal.source_digest,
        500,
    );

    let mut kernel = Kernel::new(Policy::default()).expect("kernel");
    let mut runtime = Runtime::default();
    let result = integration::run_with_artifact(
        &mut kernel,
        &mut runtime,
        EvidenceBinding {
            evidence: &evidence,
            evidence_id: "artifact-evidence",
            artifacts: &artifacts,
            artifact_id: "synthetic-source",
            custody: &custody,
            custody_id: "source-custody",
        },
        &proposal,
        observation(true),
    )
    .expect("artifact-bound workflow");
    assert_eq!(result.disposition, Disposition::Completed);
    assert_eq!(
        runtime.state.get("sandbox:answer"),
        Some(&Value::String("bounded".into()))
    );
    assert_eq!(digest(&runtime.state).expect("state digest").len(), 64);
}

#[test]
fn artifact_subject_mismatch_quarantines_before_mutation() {
    let proposal = proposal("e2e-artifact-mismatch", 7);
    let evidence = accepted_evidence(&proposal, "artifact-mismatch-evidence");
    let artifacts = accepted_artifact("wrong-subject-artifact", &"5".repeat(64));
    let custody = accepted_custody(
        "source-custody",
        "synthetic-root",
        &proposal.source_digest,
        500,
    );
    let mut kernel = Kernel::new(Policy::default()).expect("kernel");
    let mut runtime = Runtime::default();

    let result = integration::run_with_artifact(
        &mut kernel,
        &mut runtime,
        EvidenceBinding {
            evidence: &evidence,
            evidence_id: "artifact-mismatch-evidence",
            artifacts: &artifacts,
            artifact_id: "wrong-subject-artifact",
            custody: &custody,
            custody_id: "source-custody",
        },
        &proposal,
        observation(true),
    )
    .expect("artifact mismatch quarantine");

    assert_eq!(result.disposition, Disposition::Quarantined);
    assert!(result.decision_digest.is_none());
    assert!(kernel.journal.entries.is_empty());
    assert!(runtime.state.is_empty());
    assert!(runtime.audit.is_empty());
}

#[test]
fn invalid_artifact_custody_quarantines_before_admission_or_mutation() {
    let proposal = proposal("e2e-invalid-custody", 8);
    let evidence = accepted_evidence(&proposal, "invalid-custody-evidence");
    let artifacts = accepted_artifact("custody-bound-source", &proposal.source_digest);

    let missing = CustodyRegistry::default();
    let wrong_digest = accepted_custody("source-custody", "synthetic-root", &"6".repeat(64), 500);
    let wrong_root = accepted_custody(
        "source-custody",
        "different-root",
        &proposal.source_digest,
        500,
    );
    let expired = accepted_custody(
        "source-custody",
        "synthetic-root",
        &proposal.source_digest,
        10,
    );
    let mut deleted = accepted_custody(
        "source-custody",
        "synthetic-root",
        &proposal.source_digest,
        500,
    );
    deleted
        .mark_deleted("source-custody", "synthetic-owner", 10)
        .expect("mark deleted");

    for custody in [&missing, &wrong_digest, &wrong_root, &expired, &deleted] {
        let mut kernel = Kernel::new(Policy::default()).expect("kernel");
        let mut runtime = Runtime::default();
        let result = integration::run_with_artifact(
            &mut kernel,
            &mut runtime,
            EvidenceBinding {
                evidence: &evidence,
                evidence_id: "invalid-custody-evidence",
                artifacts: &artifacts,
                artifact_id: "custody-bound-source",
                custody,
                custody_id: "source-custody",
            },
            &proposal,
            observation(true),
        )
        .expect("invalid custody quarantine");

        assert_eq!(result.disposition, Disposition::Quarantined);
        assert!(result.decision_digest.is_none());
        assert!(kernel.journal.entries.is_empty());
        assert!(runtime.state.is_empty());
        assert!(runtime.audit.is_empty());
    }
}

#[test]
fn combined_artifact_custody_receipt_flow_gates_execution_in_order() {
    let proposal = proposal("e2e-combined-gates", 9);
    let evidence = accepted_evidence(&proposal, "combined-gates-evidence");
    let artifacts = accepted_artifact("combined-gates-artifact", &proposal.source_digest);
    let wrong_custody = accepted_custody(
        "combined-gates-custody",
        "wrong-root",
        &proposal.source_digest,
        500,
    );
    let custody = accepted_custody(
        "combined-gates-custody",
        "synthetic-root",
        &proposal.source_digest,
        500,
    );
    let (policy, signer, receipt) = signed_receipt(&proposal);
    let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
        .expect("receipt verifier");
    let mut kernel = Kernel::new(policy).expect("kernel");
    let mut runtime = Runtime::default();

    let rejected = integration::run_with_artifact_and_receipt(
        &mut kernel,
        &mut runtime,
        EvidenceBinding {
            evidence: &evidence,
            evidence_id: "combined-gates-evidence",
            artifacts: &artifacts,
            artifact_id: "combined-gates-artifact",
            custody: &wrong_custody,
            custody_id: "combined-gates-custody",
        },
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        &proposal,
        observation(true),
    )
    .expect("custody rejection");

    assert_eq!(rejected.disposition, Disposition::Quarantined);
    assert!(rejected.decision_digest.is_none());
    assert!(kernel.journal.entries.is_empty());
    assert!(runtime.state.is_empty());
    assert!(runtime.audit.is_empty());

    let completed = integration::run_with_artifact_and_receipt(
        &mut kernel,
        &mut runtime,
        EvidenceBinding {
            evidence: &evidence,
            evidence_id: "combined-gates-evidence",
            artifacts: &artifacts,
            artifact_id: "combined-gates-artifact",
            custody: &custody,
            custody_id: "combined-gates-custody",
        },
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        &proposal,
        observation(true),
    )
    .expect("valid combined workflow");

    assert_eq!(completed.disposition, Disposition::Completed);
    assert_eq!(kernel.journal.entries.len(), 1);
    assert_eq!(
        runtime.state.get("sandbox:answer"),
        Some(&Value::String("bounded".into()))
    );
    assert_eq!(runtime.audit.len(), 1);
}

#[cfg(unix)]
#[test]
fn local_artifact_bytes_gate_execution_and_leave_receipt_reusable_on_rejection() {
    use std::os::unix::fs::PermissionsExt;

    let expected_bytes = b"the exact synthetic source artifact";
    let mut proposal = proposal("e2e-local-custody-bytes", 10);
    proposal.source_digest = digest_bytes(expected_bytes);
    let evidence = accepted_evidence(&proposal, "local-custody-evidence");
    let artifacts = accepted_artifact("local-custody-artifact", &proposal.source_digest);
    let custody = accepted_custody(
        "local-custody-record",
        "synthetic-root",
        &proposal.source_digest,
        500,
    );
    let (policy, signer, receipt) = signed_receipt(&proposal);
    let mut verifier = ReceiptVerifier::with_key(signer.key_id(), signer.verifying_key_bytes())
        .expect("receipt verifier");

    let directory = tempfile::tempdir().expect("temporary custody parent");
    let root_path = directory.path().join("custody-root");
    std::fs::create_dir(&root_path).expect("create custody root");
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))
        .expect("set custody root permissions");
    let artifact_path = root_path.join("source.bin");
    std::fs::write(&artifact_path, b"wrong artifact bytes").expect("write wrong bytes");
    std::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o600))
        .expect("set artifact permissions");
    let paths = LocalCustodyPaths {
        root_path: &root_path,
        repository_root: std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        artifact_relative_path: std::path::Path::new("source.bin"),
        max_bytes: 1024,
    };

    let mut kernel = Kernel::new(policy).expect("kernel");
    let mut runtime = Runtime::default();
    let rejected = integration::run_with_local_artifact_and_receipt(
        &mut kernel,
        &mut runtime,
        EvidenceBinding {
            evidence: &evidence,
            evidence_id: "local-custody-evidence",
            artifacts: &artifacts,
            artifact_id: "local-custody-artifact",
            custody: &custody,
            custody_id: "local-custody-record",
        },
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        paths,
        &proposal,
        observation(true),
    )
    .expect("wrong local bytes quarantine");

    assert_eq!(rejected.disposition, Disposition::Quarantined);
    assert!(rejected.decision_digest.is_none());
    assert!(kernel.journal.entries.is_empty());
    assert!(runtime.state.is_empty());
    assert!(runtime.audit.is_empty());

    std::fs::write(&artifact_path, expected_bytes).expect("replace with exact bytes");
    let completed = integration::run_with_local_artifact_and_receipt(
        &mut kernel,
        &mut runtime,
        EvidenceBinding {
            evidence: &evidence,
            evidence_id: "local-custody-evidence",
            artifacts: &artifacts,
            artifact_id: "local-custody-artifact",
            custody: &custody,
            custody_id: "local-custody-record",
        },
        ReceiptBinding {
            verifier: &mut verifier,
            receipt: &receipt,
            subject: "synthetic-tenant",
        },
        paths,
        &proposal,
        observation(true),
    )
    .expect("corrected local artifact completes");

    assert_eq!(completed.disposition, Disposition::Completed);
    assert_eq!(kernel.journal.entries.len(), 1);
    assert_eq!(
        runtime.state.get("sandbox:answer"),
        Some(&Value::String("bounded".into()))
    );
    assert_eq!(runtime.audit.len(), 1);
}
