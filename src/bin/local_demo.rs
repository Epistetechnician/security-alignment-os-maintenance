//! Deterministic local demonstration of the evidence -> admission -> runtime path.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::{
    integration, Action, Claim, Evidence, EvidenceRegistry, Kernel, Policy, Proposal, Runtime,
};
use serde_json::Value;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = Proposal {
        candidate_id: "local-demo".into(),
        agent_id: "demo-agent".into(),
        intent: "write a bounded local value".into(),
        action: Action::Write,
        scope: "sandbox".into(),
        payload: [
            ("key".into(), Value::String("sandbox:answer".into())),
            ("value".into(), Value::Number(42.into())),
        ]
        .into_iter()
        .collect(),
        resource_cost: [
            ("cpu_ms".into(), 1),
            ("bytes".into(), 2),
            ("spend".into(), 0),
        ]
        .into_iter()
        .collect(),
        source_digest: "b".repeat(64),
        claims: vec![Claim {
            guarantees: vec!["PolicyCompliance".into()],
            assumptions: vec![],
            excludes: vec!["alignment".into()],
            maturity: 1,
            trust_roots: vec!["local".into()],
            valid_until: 100,
            provenance_digest: "a".repeat(64),
        }],
        nonce: 1,
        expires_at: 50,
        requests_direct_authority: false,
    };
    let subject = proposal.digest()?;
    let mut evidence = EvidenceRegistry::default();
    evidence.insert(Evidence {
        id: "demo-evidence".into(),
        source_digest: subject,
        operator_id: "operator".into(),
        validator_id: "validator".into(),
        reviewer_id: "".into(),
        valid_until: 100,
        accepted: false,
        revoked: false,
    })?;
    evidence.accept("demo-evidence", "reviewer")?;

    let mut kernel = Kernel::new(Policy::default())?;
    let mut runtime = Runtime::default();
    let result = integration::run(
        &mut kernel,
        &mut runtime,
        &evidence,
        "demo-evidence",
        &proposal,
        integration::Observation {
            at: 10,
            healthy: true,
            telemetry_present: true,
            kill_requested: false,
        },
    )?;
    let mut output = BTreeMap::new();
    output.insert("result", serde_json::to_value(result)?);
    output.insert(
        "state_digest",
        serde_json::to_value(security_alignment_os::digest(&runtime.state)?)?,
    );
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
