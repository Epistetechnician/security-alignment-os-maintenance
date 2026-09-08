//! Signed, pure-data replication records for the fixed maintenance operation.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module accepts exactly two signed host reports for the one fixed
//! maintenance process. It binds the reports to the same request, checkout
//! baseline, process version, implementation revision, and containment or
//! recovery scenarios. Host and operator labels are caller assertions; the
//! signatures authenticate possession of the report keys, not a physical host
//! or an independent human operator.

use crate::maintenance_process::{
    fixed_input_digest, fixed_policy_digest, fixed_tests_digest, PROCESS_VERSION,
};
use crate::{canonical_bytes, digest, valid_digest, Error, Result, STATE_SLICE};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const REPLICATION_VERSION: u8 = 1;
pub const FIXED_OPERATION_IDENTITY: &str = crate::maintenance_process::FIXED_INPUT_IDENTITY;
pub const REPLICATION_CLAIM_CEILING: &str =
    "local signed wire-consistency evidence for this fixed maintenance operation only";
pub const REQUIRED_SCENARIOS: [&str; 8] = [
    "authorized-completion",
    "evaluation-expiry",
    "pre-finalization-cancellation",
    "pre-finalization-expiry",
    "concurrent-target-change",
    "neighbor-change-recovery",
    "shared-checkout-lock",
    "replacement-lock-ownership",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ScenarioStatus {
    Applied,
    Quarantined,
    RolledBack,
    Frozen,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RecoveryDisposition {
    AuthorizedChangeCommitted,
    NoMutation,
    BaselineRestored,
    ExternalChangePreservedAndFrozen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioResult {
    pub scenario_id: String,
    pub status: ScenarioStatus,
    pub recovery: RecoveryDisposition,
    pub final_checkout_digest: String,
    /// Digest of the operator-supplied local reproduction evidence.
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostReport {
    pub version: u8,
    pub state_slice: String,
    pub operation: String,
    pub process_version: u8,
    /// Exact source revision used for the fixed operation.
    pub implementation_revision: String,
    pub request_digest: String,
    pub checkout_baseline_digest: String,
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub evaluator_public_key: String,
    pub evaluator_timeout_ms: u64,
    pub claim_ceiling: String,
    pub host_id: String,
    pub operator_id: String,
    /// Lowercase hexadecimal Ed25519 verification key for the host signer.
    pub host_public_key: String,
    /// Lowercase hexadecimal Ed25519 verification key for the operator signer.
    pub operator_public_key: String,
    pub scenarios: Vec<ScenarioResult>,
    pub report_id: String,
    /// Signature over every report field except both signatures.
    pub host_signature: String,
    pub operator_signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplicationPacket {
    pub version: u8,
    pub state_slice: String,
    pub operation: String,
    pub process_version: u8,
    pub implementation_revision: String,
    pub request_digest: String,
    pub checkout_baseline_digest: String,
    pub evaluator_executable_digest: String,
    pub evaluator_input_digest: String,
    pub evaluator_tests_digest: String,
    pub policy_digest: String,
    pub evaluator_public_key: String,
    pub evaluator_timeout_ms: u64,
    pub claim_ceiling: String,
    pub reports: Vec<HostReport>,
    pub packet_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct ReportIdentityPayload<'a> {
    version: u8,
    state_slice: &'a str,
    operation: &'a str,
    process_version: u8,
    implementation_revision: &'a str,
    request_digest: &'a str,
    checkout_baseline_digest: &'a str,
    evaluator_executable_digest: &'a str,
    evaluator_input_digest: &'a str,
    evaluator_tests_digest: &'a str,
    policy_digest: &'a str,
    evaluator_public_key: &'a str,
    evaluator_timeout_ms: u64,
    claim_ceiling: &'a str,
    host_id: &'a str,
    operator_id: &'a str,
    host_public_key: &'a str,
    operator_public_key: &'a str,
    scenarios: &'a [ScenarioResult],
}

#[derive(Clone, Debug, Serialize)]
struct ReportSigningPayload<'a> {
    version: u8,
    state_slice: &'a str,
    operation: &'a str,
    process_version: u8,
    implementation_revision: &'a str,
    request_digest: &'a str,
    checkout_baseline_digest: &'a str,
    evaluator_executable_digest: &'a str,
    evaluator_input_digest: &'a str,
    evaluator_tests_digest: &'a str,
    policy_digest: &'a str,
    evaluator_public_key: &'a str,
    evaluator_timeout_ms: u64,
    claim_ceiling: &'a str,
    host_id: &'a str,
    operator_id: &'a str,
    host_public_key: &'a str,
    operator_public_key: &'a str,
    scenarios: &'a [ScenarioResult],
    report_id: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct PacketIdentityPayload<'a> {
    version: u8,
    state_slice: &'a str,
    operation: &'a str,
    process_version: u8,
    implementation_revision: &'a str,
    request_digest: &'a str,
    checkout_baseline_digest: &'a str,
    evaluator_executable_digest: &'a str,
    evaluator_input_digest: &'a str,
    evaluator_tests_digest: &'a str,
    policy_digest: &'a str,
    evaluator_public_key: &'a str,
    evaluator_timeout_ms: u64,
    claim_ceiling: &'a str,
    report_ids: Vec<String>,
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_public_key(value: &str) -> bool {
    decode_fixed::<32>(value)
        .and_then(|bytes| {
            VerifyingKey::from_bytes(&bytes)
                .map(|_| ())
                .map_err(|_| Error::Rejected("replication public key is invalid".into()))
        })
        .is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Rejected(
            "replication hex field has wrong length".into(),
        ));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (pair[0] as char)
            .to_digit(16)
            .and_then(|high| {
                (pair[1] as char)
                    .to_digit(16)
                    .map(|low| ((high << 4) | low) as u8)
            })
            .ok_or_else(|| Error::Rejected("replication hex field is malformed".into()))?;
    }
    Ok(output)
}

fn expected_scenario(scenario_id: &str) -> Option<(ScenarioStatus, RecoveryDisposition)> {
    match scenario_id {
        "authorized-completion" => Some((
            ScenarioStatus::Applied,
            RecoveryDisposition::AuthorizedChangeCommitted,
        )),
        "evaluation-expiry" => Some((ScenarioStatus::Quarantined, RecoveryDisposition::NoMutation)),
        "pre-finalization-cancellation" => Some((
            ScenarioStatus::RolledBack,
            RecoveryDisposition::BaselineRestored,
        )),
        "pre-finalization-expiry" => Some((
            ScenarioStatus::RolledBack,
            RecoveryDisposition::BaselineRestored,
        )),
        "concurrent-target-change" => Some((
            ScenarioStatus::Frozen,
            RecoveryDisposition::ExternalChangePreservedAndFrozen,
        )),
        "neighbor-change-recovery" => Some((
            ScenarioStatus::Frozen,
            RecoveryDisposition::ExternalChangePreservedAndFrozen,
        )),
        "shared-checkout-lock" | "replacement-lock-ownership" => {
            Some((ScenarioStatus::Blocked, RecoveryDisposition::NoMutation))
        }
        _ => None,
    }
}

impl HostReport {
    fn identity_payload(&self) -> ReportIdentityPayload<'_> {
        ReportIdentityPayload {
            version: self.version,
            state_slice: &self.state_slice,
            operation: &self.operation,
            process_version: self.process_version,
            implementation_revision: &self.implementation_revision,
            request_digest: &self.request_digest,
            checkout_baseline_digest: &self.checkout_baseline_digest,
            evaluator_executable_digest: &self.evaluator_executable_digest,
            evaluator_input_digest: &self.evaluator_input_digest,
            evaluator_tests_digest: &self.evaluator_tests_digest,
            policy_digest: &self.policy_digest,
            evaluator_public_key: &self.evaluator_public_key,
            evaluator_timeout_ms: self.evaluator_timeout_ms,
            claim_ceiling: &self.claim_ceiling,
            host_id: &self.host_id,
            operator_id: &self.operator_id,
            host_public_key: &self.host_public_key,
            operator_public_key: &self.operator_public_key,
            scenarios: &self.scenarios,
        }
    }

    fn signing_payload(&self) -> ReportSigningPayload<'_> {
        ReportSigningPayload {
            version: self.version,
            state_slice: &self.state_slice,
            operation: &self.operation,
            process_version: self.process_version,
            implementation_revision: &self.implementation_revision,
            request_digest: &self.request_digest,
            checkout_baseline_digest: &self.checkout_baseline_digest,
            evaluator_executable_digest: &self.evaluator_executable_digest,
            evaluator_input_digest: &self.evaluator_input_digest,
            evaluator_tests_digest: &self.evaluator_tests_digest,
            policy_digest: &self.policy_digest,
            evaluator_public_key: &self.evaluator_public_key,
            evaluator_timeout_ms: self.evaluator_timeout_ms,
            claim_ceiling: &self.claim_ceiling,
            host_id: &self.host_id,
            operator_id: &self.operator_id,
            host_public_key: &self.host_public_key,
            operator_public_key: &self.operator_public_key,
            scenarios: &self.scenarios,
            report_id: &self.report_id,
        }
    }

    fn expected_id(&self) -> Result<String> {
        digest(&self.identity_payload())
    }

    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(&self.signing_payload())
    }

    /// Signs this report with distinct host and operator keys.
    pub fn sign_with_seeds(&mut self, host_seed: [u8; 32], operator_seed: [u8; 32]) -> Result<()> {
        let host_key = SigningKey::from_bytes(&host_seed);
        let operator_key = SigningKey::from_bytes(&operator_seed);
        self.host_public_key = hex_encode(host_key.verifying_key().as_bytes());
        self.operator_public_key = hex_encode(operator_key.verifying_key().as_bytes());
        self.report_id = self.expected_id()?;
        let unsigned = self.unsigned_bytes()?;
        self.host_signature = hex_encode(&host_key.sign(&unsigned).to_bytes());
        self.operator_signature = hex_encode(&operator_key.sign(&unsigned).to_bytes());
        self.validate()
    }

    fn validate_shape(&self) -> Result<()> {
        if self.version != REPLICATION_VERSION
            || self.state_slice != STATE_SLICE
            || self.operation != FIXED_OPERATION_IDENTITY
            || self.process_version != PROCESS_VERSION
            || !valid_revision(&self.implementation_revision)
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.checkout_baseline_digest)
            || !valid_digest(&self.evaluator_executable_digest)
            || self.evaluator_input_digest != fixed_input_digest()
            || self.evaluator_tests_digest != fixed_tests_digest()
            || self.policy_digest != fixed_policy_digest()
            || !valid_public_key(&self.evaluator_public_key)
            || self.evaluator_timeout_ms == 0
            || self.evaluator_timeout_ms > 60_000
            || self.claim_ceiling != REPLICATION_CLAIM_CEILING
            || !valid_text(&self.host_id)
            || !valid_text(&self.operator_id)
            || self.host_id == self.operator_id
            || !valid_public_key(&self.host_public_key)
            || !valid_public_key(&self.operator_public_key)
            || self.host_public_key == self.operator_public_key
            || self.scenarios.len() != REQUIRED_SCENARIOS.len()
            || !valid_digest(&self.report_id)
            || decode_fixed::<64>(&self.host_signature).is_err()
            || decode_fixed::<64>(&self.operator_signature).is_err()
        {
            return Err(Error::Rejected(
                "maintenance host report shape is invalid".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (scenario, expected_id) in self.scenarios.iter().zip(REQUIRED_SCENARIOS) {
            let Some((expected_status, expected_recovery)) = expected_scenario(expected_id) else {
                return Err(Error::Rejected(
                    "maintenance scenario contract is invalid".into(),
                ));
            };
            if scenario.scenario_id != expected_id
                || !seen.insert(scenario.scenario_id.clone())
                || scenario.status != expected_status
                || scenario.recovery != expected_recovery
                || !valid_digest(&scenario.final_checkout_digest)
                || !valid_digest(&scenario.evidence_digest)
            {
                return Err(Error::Rejected(
                    "maintenance scenario result is invalid".into(),
                ));
            }
            let must_match_baseline = matches!(
                scenario.recovery,
                RecoveryDisposition::NoMutation | RecoveryDisposition::BaselineRestored
            );
            if must_match_baseline
                != (scenario.final_checkout_digest == self.checkout_baseline_digest)
            {
                return Err(Error::Rejected(
                    "maintenance scenario baseline result is inconsistent".into(),
                ));
            }
        }
        if self.report_id != self.expected_id()? {
            return Err(Error::Rejected(
                "maintenance host report identity mismatch".into(),
            ));
        }
        Ok(())
    }

    fn verify_one_signature(&self, public_key: &str, signature: &str) -> Result<()> {
        let key = VerifyingKey::from_bytes(&decode_fixed::<32>(public_key)?)
            .map_err(|_| Error::Rejected("maintenance host key is invalid".into()))?;
        let signature = Signature::from_bytes(&decode_fixed::<64>(signature)?);
        key.verify(&self.unsigned_bytes()?, &signature)
            .map_err(|_| Error::Rejected("maintenance host report signature is invalid".into()))
    }

    pub fn verify_signatures(&self) -> Result<()> {
        self.verify_one_signature(&self.host_public_key, &self.host_signature)?;
        self.verify_one_signature(&self.operator_public_key, &self.operator_signature)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        self.verify_signatures()
    }
}

impl ReplicationPacket {
    fn identity_payload(&self) -> PacketIdentityPayload<'_> {
        let report_ids = self
            .reports
            .iter()
            .map(|report| report.report_id.clone())
            .collect::<Vec<_>>();
        PacketIdentityPayload {
            version: self.version,
            state_slice: &self.state_slice,
            operation: &self.operation,
            process_version: self.process_version,
            implementation_revision: &self.implementation_revision,
            request_digest: &self.request_digest,
            checkout_baseline_digest: &self.checkout_baseline_digest,
            evaluator_executable_digest: &self.evaluator_executable_digest,
            evaluator_input_digest: &self.evaluator_input_digest,
            evaluator_tests_digest: &self.evaluator_tests_digest,
            policy_digest: &self.policy_digest,
            evaluator_public_key: &self.evaluator_public_key,
            evaluator_timeout_ms: self.evaluator_timeout_ms,
            claim_ceiling: &self.claim_ceiling,
            report_ids,
        }
    }

    fn expected_id(&self) -> Result<String> {
        digest(&self.identity_payload())
    }

    /// Constructs a packet from exactly two reports and canonicalizes report order.
    pub fn from_reports(mut reports: Vec<HostReport>) -> Result<Self> {
        if reports.len() != 2 {
            return Err(Error::Rejected(
                "maintenance replication requires exactly two host reports".into(),
            ));
        }
        for report in &reports {
            report.validate()?;
        }
        reports.sort_by(|left, right| left.host_id.cmp(&right.host_id));
        let first = &reports[0];
        let packet = Self {
            version: REPLICATION_VERSION,
            state_slice: STATE_SLICE.into(),
            operation: FIXED_OPERATION_IDENTITY.into(),
            process_version: PROCESS_VERSION,
            implementation_revision: first.implementation_revision.clone(),
            request_digest: first.request_digest.clone(),
            checkout_baseline_digest: first.checkout_baseline_digest.clone(),
            evaluator_executable_digest: first.evaluator_executable_digest.clone(),
            evaluator_input_digest: first.evaluator_input_digest.clone(),
            evaluator_tests_digest: first.evaluator_tests_digest.clone(),
            policy_digest: first.policy_digest.clone(),
            evaluator_public_key: first.evaluator_public_key.clone(),
            evaluator_timeout_ms: first.evaluator_timeout_ms,
            claim_ceiling: first.claim_ceiling.clone(),
            reports,
            packet_id: String::new(),
        };
        let mut packet = packet;
        packet.packet_id = packet.expected_id()?;
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != REPLICATION_VERSION
            || self.state_slice != STATE_SLICE
            || self.operation != FIXED_OPERATION_IDENTITY
            || self.process_version != PROCESS_VERSION
            || !valid_revision(&self.implementation_revision)
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.checkout_baseline_digest)
            || !valid_digest(&self.evaluator_executable_digest)
            || self.evaluator_input_digest != fixed_input_digest()
            || self.evaluator_tests_digest != fixed_tests_digest()
            || self.policy_digest != fixed_policy_digest()
            || !valid_public_key(&self.evaluator_public_key)
            || self.evaluator_timeout_ms == 0
            || self.evaluator_timeout_ms > 60_000
            || self.claim_ceiling != REPLICATION_CLAIM_CEILING
            || self.reports.len() != 2
            || !valid_digest(&self.packet_id)
            || self.reports[0].host_id >= self.reports[1].host_id
        {
            return Err(Error::Rejected(
                "maintenance replication packet shape is invalid".into(),
            ));
        }
        let mut hosts = BTreeSet::new();
        let mut operators = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut reports = BTreeSet::new();
        for report in &self.reports {
            report.validate()?;
            if report.state_slice != self.state_slice
                || report.operation != self.operation
                || report.process_version != self.process_version
                || report.implementation_revision != self.implementation_revision
                || report.request_digest != self.request_digest
                || report.checkout_baseline_digest != self.checkout_baseline_digest
                || report.evaluator_executable_digest != self.evaluator_executable_digest
                || report.evaluator_input_digest != self.evaluator_input_digest
                || report.evaluator_tests_digest != self.evaluator_tests_digest
                || report.policy_digest != self.policy_digest
                || report.evaluator_public_key != self.evaluator_public_key
                || report.evaluator_timeout_ms != self.evaluator_timeout_ms
                || report.claim_ceiling != self.claim_ceiling
                || !hosts.insert(report.host_id.clone())
                || !operators.insert(report.operator_id.clone())
                || !keys.insert(report.host_public_key.clone())
                || !keys.insert(report.operator_public_key.clone())
                || !reports.insert(report.report_id.clone())
            {
                return Err(Error::Rejected(
                    "maintenance replication reports are not independent".into(),
                ));
            }
        }
        if self.packet_id != self.expected_id()? {
            return Err(Error::Rejected(
                "maintenance replication packet identity mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Serializes a validated packet using the exact canonical wire shape.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self)
    }

    /// Parses only canonical JSON, rejecting duplicate-key or formatting variants.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let packet: Self = serde_json::from_slice(bytes)?;
        if canonical_bytes(&packet)? != bytes {
            return Err(Error::Rejected(
                "maintenance replication bytes are not canonical JSON".into(),
            ));
        }
        packet.validate()?;
        Ok(packet)
    }
}
