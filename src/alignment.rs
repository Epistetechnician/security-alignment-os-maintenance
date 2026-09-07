//! Prediction/configuration locks without model execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{digest, Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredictionLock {
    pub protocol_digest: String,
    pub prediction_digest: String,
    pub configuration_digest: String,
    pub fit_complete: bool,
    pub independent_accept: bool,
}

impl PredictionLock {
    pub fn new(protocol: &str, predictions: &str, configuration: &str) -> Result<Self> {
        if protocol.is_empty() || predictions.is_empty() || configuration.is_empty() {
            return Err(Error::Invalid("lock inputs must be non-empty".into()));
        }
        Ok(Self {
            protocol_digest: digest(&protocol)?,
            prediction_digest: digest(&predictions)?,
            configuration_digest: digest(&configuration)?,
            fit_complete: false,
            independent_accept: false,
        })
    }
    pub fn lock_fit(&mut self) {
        self.fit_complete = true;
    }
    pub fn accept_independently(&mut self) {
        self.independent_accept = true;
    }
    pub fn assessment_eligible(&self) -> bool {
        self.fit_complete && self.independent_accept
    }
    pub fn validate(&self) -> Result<()> {
        if !self.assessment_eligible() {
            return Err(Error::Quarantined(
                "prediction or independent acceptance lock is missing".into(),
            ));
        }
        Ok(())
    }
}
