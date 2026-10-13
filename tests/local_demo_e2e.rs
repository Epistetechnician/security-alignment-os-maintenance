//! Executable contract test for the public local demonstration.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use security_alignment_os::{digest, CLAIM_CEILING, STATE_SLICE};
use serde_json::Value;
use std::collections::BTreeMap;
use std::process::Command;

#[test]
fn local_demo_reports_completion_and_the_bounded_claim() {
    let output = Command::new(env!("CARGO_BIN_EXE_local_demo"))
        .output()
        .expect("run local demo binary");
    assert!(
        output.status.success(),
        "local demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("demo JSON");
    assert_eq!(report["state_slice"], STATE_SLICE);
    assert_eq!(report["claim_ceiling"], CLAIM_CEILING);
    assert_eq!(report["result"]["disposition"], "Completed");
    for digest_field in ["subject_digest", "decision_digest", "observation_digest"] {
        let value = report["result"][digest_field]
            .as_str()
            .expect("workflow digest");
        assert_eq!(value.len(), 64, "{digest_field}");
        assert!(value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    let expected_state = BTreeMap::from([("sandbox:answer".to_owned(), Value::from(42))]);
    assert_eq!(
        report["state_digest"],
        digest(&expected_state).expect("state digest")
    );
}
