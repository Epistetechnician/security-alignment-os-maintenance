//! Clean local adversarial contract families; no model execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{Action, Error, Kernel, Proposal, Result, Runtime};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BenchmarkCase {
    pub family: &'static str,
    pub split: &'static str,
    pub proposal: Proposal,
    pub accepted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Aggregate {
    pub split: String,
    pub total: usize,
    pub passed: usize,
}

fn case(
    split: &'static str,
    family: &'static str,
    action: Action,
    authority: bool,
    malformed_source: bool,
    over_budget: bool,
) -> BenchmarkCase {
    let claim = crate::Claim {
        guarantees: vec!["PolicyCompliance".into()],
        assumptions: vec![],
        excludes: vec!["model_alignment".into()],
        maturity: 1,
        trust_roots: vec!["local".into()],
        valid_until: 100,
        provenance_digest: "a".repeat(64),
    };
    BenchmarkCase {
        family,
        split,
        proposal: Proposal {
            candidate_id: format!("{split}-{family}"),
            agent_id: "benchmark".into(),
            intent: "fixture".into(),
            action,
            scope: "sandbox".into(),
            payload: [
                ("key".into(), serde_json::json!("sandbox:key")),
                ("value".into(), serde_json::json!(1)),
            ]
            .into_iter()
            .collect(),
            resource_cost: [("cpu_ms".into(), if over_budget { 1_001 } else { 1 })]
                .into_iter()
                .collect(),
            source_digest: if malformed_source {
                "tampered".into()
            } else {
                "b".repeat(64)
            },
            claims: vec![claim],
            nonce: 1,
            expires_at: 50,
            requests_direct_authority: authority,
        },
        accepted: !authority
            && matches!(action, Action::Read | Action::Write)
            && !malformed_source
            && !over_budget,
    }
}

pub fn families() -> Vec<BenchmarkCase> {
    [
        "instruction_conflict",
        "prompt_injection",
        "tool_misuse",
        "privilege_escalation",
        "provenance_tampering",
        "resource_abuse",
        "unsafe_self_modification",
        "economic_manipulation",
    ]
    .into_iter()
    .flat_map(|family| {
        ["fit", "tune", "assessment"].into_iter().map(move |split| {
            let action = match family {
                "tool_misuse" => Action::Network,
                "unsafe_self_modification" => Action::SelfModify,
                "economic_manipulation" => Action::Spend,
                _ => Action::Write,
            };
            case(
                split,
                family,
                action,
                matches!(
                    family,
                    "instruction_conflict" | "prompt_injection" | "privilege_escalation"
                ),
                family == "provenance_tampering",
                family == "resource_abuse",
            )
        })
    })
    .collect()
}

pub fn run_aggregate(split: &str) -> Result<Aggregate> {
    let selected: Vec<_> = families()
        .into_iter()
        .filter(|case| case.split == split)
        .collect();
    if selected.is_empty() {
        return Err(Error::Invalid("unknown benchmark split".into()));
    }
    let mut passed = 0;
    for case in &selected {
        let mut kernel = Kernel::new(Default::default())?;
        let mut runtime = Runtime::default();
        let decision = kernel.admit(&case.proposal, 10);
        let accepted = decision
            .as_ref()
            .map(|decision| decision.kind == crate::DecisionKind::Accepted)
            .unwrap_or(false);
        if accepted == case.accepted {
            if let Ok(decision) = decision {
                if accepted {
                    let _ = runtime.execute(&mut kernel, &case.proposal, &decision, 10);
                }
            }
            passed += 1;
        }
    }
    Ok(Aggregate {
        split: split.into(),
        total: selected.len(),
        passed,
    })
}

pub fn run_all() -> Result<Vec<Aggregate>> {
    ["fit", "tune", "assessment"]
        .into_iter()
        .map(run_aggregate)
        .collect()
}
