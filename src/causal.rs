//! Preregistered causal-measurement contract without model execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module freezes the identities needed for a future causal protocol and
//! enforces qualification, prediction locking, held-out assessment, custody
//! retention, and independent acceptance order. It stores no raw traces and
//! makes no behavioral, alignment, consciousness, or human-benefit claim.

use crate::{canonical_bytes, digest, valid_digest, Error, Result, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const SCHEMA_VERSION: &str = "security-alignment-os-causal-protocol-v1";
const CLAIM_CEILING: &str = "LocalCausalQualification";
const MAX_TEXT_LEN: usize = 256;

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_LEN && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CausalTrack {
    Behavioral,
    Mechanistic,
    ScalableOversight,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CausalState {
    Draft,
    Qualified,
    AssessmentLocked,
    Accepted,
    Closed,
}

/// Inputs frozen before a causal protocol record is created.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalProtocolInputs {
    pub protocol_id: String,
    pub researcher_id: String,
    pub validator_id: String,
    pub track: CausalTrack,
    pub model_digest: String,
    pub runtime_digest: String,
    pub asset_manifest_digest: String,
    pub corpus_digest: String,
    pub split_digest: String,
    pub held_out_split_digest: String,
    pub wrapper_digest: String,
    pub feature_digest: String,
    pub estimand_digest: String,
    pub intervention_digest: String,
    pub control_digest: String,
    pub power_digest: String,
    pub multiplicity_digest: String,
    pub repeat_digest: String,
    pub attrition_digest: String,
    pub prediction_lock_digest: String,
    pub custody_digest: String,
    pub validator_config_digest: String,
    pub raw_trace_retention_until: u64,
}

/// Versioned protocol record whose state transitions are prerequisites only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalProtocol {
    pub schema_version: String,
    pub state_slice: String,
    pub claim_ceiling: String,
    pub protocol_id: String,
    pub researcher_id: String,
    pub validator_id: String,
    pub track: CausalTrack,
    pub model_digest: String,
    pub runtime_digest: String,
    pub asset_manifest_digest: String,
    pub corpus_digest: String,
    pub split_digest: String,
    pub held_out_split_digest: String,
    pub wrapper_digest: String,
    pub feature_digest: String,
    pub estimand_digest: String,
    pub intervention_digest: String,
    pub control_digest: String,
    pub power_digest: String,
    pub multiplicity_digest: String,
    pub repeat_digest: String,
    pub attrition_digest: String,
    pub prediction_lock_digest: String,
    pub custody_digest: String,
    pub validator_config_digest: String,
    pub raw_trace_retention_until: u64,
    pub raw_traces_retained: bool,
    pub state: CausalState,
    pub qualification_digest: Option<String>,
    pub assessment_digest: Option<String>,
    pub acceptance_digest: Option<String>,
    pub close_reason_digest: Option<String>,
    pub protocol_digest: String,
}

impl CausalProtocol {
    pub fn new(inputs: CausalProtocolInputs) -> Result<Self> {
        let mut protocol = Self {
            schema_version: SCHEMA_VERSION.into(),
            state_slice: STATE_SLICE.into(),
            claim_ceiling: CLAIM_CEILING.into(),
            protocol_id: inputs.protocol_id,
            researcher_id: inputs.researcher_id,
            validator_id: inputs.validator_id,
            track: inputs.track,
            model_digest: inputs.model_digest,
            runtime_digest: inputs.runtime_digest,
            asset_manifest_digest: inputs.asset_manifest_digest,
            corpus_digest: inputs.corpus_digest,
            split_digest: inputs.split_digest,
            held_out_split_digest: inputs.held_out_split_digest,
            wrapper_digest: inputs.wrapper_digest,
            feature_digest: inputs.feature_digest,
            estimand_digest: inputs.estimand_digest,
            intervention_digest: inputs.intervention_digest,
            control_digest: inputs.control_digest,
            power_digest: inputs.power_digest,
            multiplicity_digest: inputs.multiplicity_digest,
            repeat_digest: inputs.repeat_digest,
            attrition_digest: inputs.attrition_digest,
            prediction_lock_digest: inputs.prediction_lock_digest,
            custody_digest: inputs.custody_digest,
            validator_config_digest: inputs.validator_config_digest,
            raw_trace_retention_until: inputs.raw_trace_retention_until,
            raw_traces_retained: false,
            state: CausalState::Draft,
            qualification_digest: None,
            assessment_digest: None,
            acceptance_digest: None,
            close_reason_digest: None,
            protocol_digest: String::new(),
        };
        protocol.validate_body()?;
        protocol.protocol_digest = protocol.expected_digest()?;
        protocol.validate()?;
        Ok(protocol)
    }

    fn validate_body(&self) -> Result<()> {
        let digests = [
            &self.model_digest,
            &self.runtime_digest,
            &self.asset_manifest_digest,
            &self.corpus_digest,
            &self.split_digest,
            &self.held_out_split_digest,
            &self.wrapper_digest,
            &self.feature_digest,
            &self.estimand_digest,
            &self.intervention_digest,
            &self.control_digest,
            &self.power_digest,
            &self.multiplicity_digest,
            &self.repeat_digest,
            &self.attrition_digest,
            &self.prediction_lock_digest,
            &self.custody_digest,
            &self.validator_config_digest,
        ];
        let state_digests = [
            self.qualification_digest.as_ref(),
            self.assessment_digest.as_ref(),
            self.acceptance_digest.as_ref(),
            self.close_reason_digest.as_ref(),
        ];
        if self.schema_version != SCHEMA_VERSION
            || self.state_slice != STATE_SLICE
            || self.claim_ceiling != CLAIM_CEILING
            || !valid_text(&self.protocol_id)
            || !valid_text(&self.researcher_id)
            || !valid_text(&self.validator_id)
            || self.researcher_id == self.validator_id
            || digests.iter().any(|value| !valid_digest(value))
            || state_digests
                .iter()
                .flatten()
                .any(|value| !valid_digest(value))
            || self.raw_trace_retention_until == 0
            || self.raw_traces_retained
        {
            return Err(Error::Invalid("causal protocol is malformed".into()));
        }
        match self.state {
            CausalState::Draft => {
                if self.qualification_digest.is_some()
                    || self.assessment_digest.is_some()
                    || self.acceptance_digest.is_some()
                    || self.close_reason_digest.is_some()
                {
                    return Err(Error::Invalid("draft causal protocol has evidence".into()));
                }
            }
            CausalState::Qualified => {
                if self.qualification_digest.is_none()
                    || self.assessment_digest.is_some()
                    || self.acceptance_digest.is_some()
                    || self.close_reason_digest.is_some()
                {
                    return Err(Error::Invalid(
                        "qualified causal protocol is inconsistent".into(),
                    ));
                }
            }
            CausalState::AssessmentLocked => {
                if self.qualification_digest.is_none()
                    || self.assessment_digest.is_none()
                    || self.acceptance_digest.is_some()
                    || self.close_reason_digest.is_some()
                {
                    return Err(Error::Invalid(
                        "locked causal assessment is inconsistent".into(),
                    ));
                }
            }
            CausalState::Accepted => {
                if self.qualification_digest.is_none()
                    || self.assessment_digest.is_none()
                    || self.acceptance_digest.is_none()
                    || self.close_reason_digest.is_some()
                {
                    return Err(Error::Invalid(
                        "accepted causal protocol is incomplete".into(),
                    ));
                }
            }
            CausalState::Closed => {
                if self.close_reason_digest.is_none() {
                    return Err(Error::Invalid("closed causal protocol lacks reason".into()));
                }
            }
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String> {
        digest(&CausalIdentity {
            schema_version: &self.schema_version,
            state_slice: &self.state_slice,
            claim_ceiling: &self.claim_ceiling,
            protocol_id: &self.protocol_id,
            researcher_id: &self.researcher_id,
            validator_id: &self.validator_id,
            track: self.track,
            model_digest: &self.model_digest,
            runtime_digest: &self.runtime_digest,
            asset_manifest_digest: &self.asset_manifest_digest,
            corpus_digest: &self.corpus_digest,
            split_digest: &self.split_digest,
            held_out_split_digest: &self.held_out_split_digest,
            wrapper_digest: &self.wrapper_digest,
            feature_digest: &self.feature_digest,
            estimand_digest: &self.estimand_digest,
            intervention_digest: &self.intervention_digest,
            control_digest: &self.control_digest,
            power_digest: &self.power_digest,
            multiplicity_digest: &self.multiplicity_digest,
            repeat_digest: &self.repeat_digest,
            attrition_digest: &self.attrition_digest,
            prediction_lock_digest: &self.prediction_lock_digest,
            custody_digest: &self.custody_digest,
            validator_config_digest: &self.validator_config_digest,
            raw_trace_retention_until: self.raw_trace_retention_until,
            raw_traces_retained: self.raw_traces_retained,
            state: self.state,
            qualification_digest: &self.qualification_digest,
            assessment_digest: &self.assessment_digest,
            acceptance_digest: &self.acceptance_digest,
            close_reason_digest: &self.close_reason_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_body()?;
        if !valid_digest(&self.protocol_digest) || self.protocol_digest != self.expected_digest()? {
            return Err(Error::Invalid("causal protocol digest mismatch".into()));
        }
        Ok(())
    }

    pub fn qualify(&mut self, qualification_digest: &str) -> Result<()> {
        if self.state != CausalState::Draft || !valid_digest(qualification_digest) {
            return Err(Error::Rejected(
                "causal qualification is unavailable".into(),
            ));
        }
        self.qualification_digest = Some(qualification_digest.into());
        self.state = CausalState::Qualified;
        self.refresh_digest()
    }

    pub fn lock_assessment(
        &mut self,
        assessment_digest: &str,
        prediction_lock_digest: &str,
    ) -> Result<()> {
        if self.state != CausalState::Qualified
            || !valid_digest(assessment_digest)
            || prediction_lock_digest != self.prediction_lock_digest
        {
            return Err(Error::Rejected(
                "causal assessment lock is unavailable or drifted".into(),
            ));
        }
        self.assessment_digest = Some(assessment_digest.into());
        self.state = CausalState::AssessmentLocked;
        self.refresh_digest()
    }

    pub fn accept_independently(
        &mut self,
        validator_id: &str,
        acceptance_digest: &str,
    ) -> Result<()> {
        if self.state != CausalState::AssessmentLocked
            || validator_id != self.validator_id
            || !valid_digest(acceptance_digest)
        {
            return Err(Error::Rejected(
                "causal independent acceptance is unavailable".into(),
            ));
        }
        self.acceptance_digest = Some(acceptance_digest.into());
        self.state = CausalState::Accepted;
        self.refresh_digest()
    }

    pub fn close(&mut self, reason_digest: &str) -> Result<()> {
        if self.state == CausalState::Closed || !valid_digest(reason_digest) {
            return Err(Error::Rejected("causal protocol is already closed".into()));
        }
        self.close_reason_digest = Some(reason_digest.into());
        self.state = CausalState::Closed;
        self.refresh_digest()
    }

    pub fn assessment_eligible(&self) -> bool {
        self.state == CausalState::Accepted
    }

    fn refresh_digest(&mut self) -> Result<()> {
        self.protocol_digest = self.expected_digest()?;
        self.validate()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(self)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let protocol: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&protocol)? != bytes {
            return Err(Error::Journal(
                "causal protocol is not canonical JSON".into(),
            ));
        }
        protocol.validate()?;
        Ok(protocol)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(protocol) => Ok(protocol),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let protocol = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(protocol)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Serialize)]
struct CausalIdentity<'a> {
    schema_version: &'a str,
    state_slice: &'a str,
    claim_ceiling: &'a str,
    protocol_id: &'a str,
    researcher_id: &'a str,
    validator_id: &'a str,
    track: CausalTrack,
    model_digest: &'a str,
    runtime_digest: &'a str,
    asset_manifest_digest: &'a str,
    corpus_digest: &'a str,
    split_digest: &'a str,
    held_out_split_digest: &'a str,
    wrapper_digest: &'a str,
    feature_digest: &'a str,
    estimand_digest: &'a str,
    intervention_digest: &'a str,
    control_digest: &'a str,
    power_digest: &'a str,
    multiplicity_digest: &'a str,
    repeat_digest: &'a str,
    attrition_digest: &'a str,
    prediction_lock_digest: &'a str,
    custody_digest: &'a str,
    validator_config_digest: &'a str,
    raw_trace_retention_until: u64,
    raw_traces_retained: bool,
    state: CausalState,
    qualification_digest: &'a Option<String>,
    assessment_digest: &'a Option<String>,
    acceptance_digest: &'a Option<String>,
    close_reason_digest: &'a Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: char) -> String {
        format!("{:064x}", value as u32)
    }

    fn protocol() -> CausalProtocol {
        CausalProtocol::new(CausalProtocolInputs {
            protocol_id: "causal-1".into(),
            researcher_id: "researcher".into(),
            validator_id: "validator".into(),
            track: CausalTrack::Behavioral,
            model_digest: digest('a'),
            runtime_digest: digest('b'),
            asset_manifest_digest: digest('c'),
            corpus_digest: digest('d'),
            split_digest: digest('e'),
            held_out_split_digest: digest('f'),
            wrapper_digest: digest('g'),
            feature_digest: digest('h'),
            estimand_digest: digest('i'),
            intervention_digest: digest('j'),
            control_digest: digest('k'),
            power_digest: digest('l'),
            multiplicity_digest: digest('m'),
            repeat_digest: digest('n'),
            attrition_digest: digest('o'),
            prediction_lock_digest: digest('p'),
            custody_digest: digest('q'),
            validator_config_digest: digest('r'),
            raw_trace_retention_until: 100,
        })
        .expect("protocol")
    }

    #[test]
    fn causal_protocol_enforces_qualification_lock_and_acceptance_order() {
        let mut value = protocol();
        assert!(value.lock_assessment(&digest('s'), &digest('p')).is_err());
        value.qualify(&digest('s')).expect("qualify");
        assert!(value.lock_assessment(&digest('t'), &digest('x')).is_err());
        value
            .lock_assessment(&digest('t'), &digest('p'))
            .expect("lock");
        assert!(value
            .accept_independently("researcher", &digest('u'))
            .is_err());
        value
            .accept_independently("validator", &digest('u'))
            .expect("accept");
        assert!(value.assessment_eligible());
    }

    #[test]
    fn protocol_identity_detects_tampering_and_recovers_canonically() {
        let value = protocol();
        let mut tampered = value.clone();
        tampered.held_out_split_digest = digest('z');
        assert!(tampered.validate().is_err());

        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("causal.json");
        value.save(&path).expect("save");
        assert_eq!(CausalProtocol::load(&path).expect("load"), value);
        let bytes = std::fs::read(&path).expect("bytes");
        std::fs::write(path.with_extension("tmp"), bytes).expect("temporary");
        std::fs::remove_file(&path).expect("primary");
        assert_eq!(CausalProtocol::recover(&path).expect("recover"), value);
    }
}
