//! Prediction/configuration locks without model execution.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::{canonical_bytes, digest, digest_bytes, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionLock {
    pub protocol_digest: String,
    pub prediction_digest: String,
    pub configuration_digest: String,
    pub fit_complete: bool,
    pub independent_accept: bool,
    lock_digest: String,
}

impl PredictionLock {
    pub fn new(protocol: &str, predictions: &str, configuration: &str) -> Result<Self> {
        if protocol.is_empty() || predictions.is_empty() || configuration.is_empty() {
            return Err(Error::Invalid("lock inputs must be non-empty".into()));
        }
        let mut lock = Self {
            protocol_digest: digest(&protocol)?,
            prediction_digest: digest(&predictions)?,
            configuration_digest: digest(&configuration)?,
            fit_complete: false,
            independent_accept: false,
            lock_digest: String::new(),
        };
        lock.refresh_digest();
        Ok(lock)
    }
    pub fn lock_fit(&mut self) {
        self.fit_complete = true;
        self.refresh_digest();
    }
    pub fn accept_independently(&mut self) {
        self.independent_accept = true;
        self.refresh_digest();
    }
    pub fn assessment_eligible(&self) -> bool {
        self.fit_complete && self.independent_accept
    }
    pub fn validate(&self) -> Result<()> {
        if !valid_digest(&self.protocol_digest)
            || !valid_digest(&self.prediction_digest)
            || !valid_digest(&self.configuration_digest)
            || !valid_digest(&self.lock_digest)
            || self.lock_digest != self.expected_digest()
        {
            return Err(Error::Invalid(
                "prediction lock digest is inconsistent".into(),
            ));
        }
        if !self.assessment_eligible() {
            return Err(Error::Quarantined(
                "prediction or independent acceptance lock is missing".into(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}\0{}\0{}",
            self.protocol_digest,
            self.prediction_digest,
            self.configuration_digest,
            self.fit_complete,
            self.independent_accept
        );
        digest_bytes(material.as_bytes())
    }

    fn refresh_digest(&mut self) {
        self.lock_digest = self.expected_digest();
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
        let lock: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&lock)? != bytes {
            return Err(Error::Journal(
                "prediction lock bytes are not canonical JSON".into(),
            ));
        }
        lock.validate()?;
        Ok(lock)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(lock) => Ok(lock),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let lock = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(lock)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prediction_lock_detects_field_tampering() {
        let mut lock =
            PredictionLock::new("protocol", "predictions", "configuration").expect("lock");
        lock.lock_fit();
        lock.accept_independently();
        lock.validate().expect("valid lock");
        lock.prediction_digest = "a".repeat(64);
        assert!(lock.validate().is_err());
    }

    #[test]
    fn prediction_lock_snapshot_is_canonical_and_recoverable() {
        let mut lock =
            PredictionLock::new("protocol", "predictions", "configuration").expect("lock");
        lock.lock_fit();
        lock.accept_independently();
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("prediction-lock.json");
        lock.save(&path).expect("save");
        assert_eq!(PredictionLock::load(&path).expect("load"), lock);
        let canonical = std::fs::read(&path).expect("canonical");
        let mut tampered = canonical.clone();
        let tamper_index = tampered.len() - 2;
        tampered[tamper_index] = b' ';
        std::fs::write(&path, tampered).expect("tamper");
        assert!(PredictionLock::load(&path).is_err());
        std::fs::write(path.with_extension("tmp"), canonical).expect("temporary");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(PredictionLock::recover(&path).expect("recover"), lock);
    }
}
