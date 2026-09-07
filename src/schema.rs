//! Versioned schema identities for cross-module record binding.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! The registry stores only caller-supplied schema names, versions, and
//! lowercase SHA-256 digests. It does not parse schemas, fetch definitions,
//! or prove that a producer followed one.

use crate::{valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATE_SLICE: &str = "security-alignment-os-foundation-v1";
const MAX_SCHEMA_ID_LEN: usize = 128;

fn valid_schema_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCHEMA_ID_LEN
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

/// A schema identity bound to an exact canonical definition digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchemaDescriptor {
    pub schema_id: String,
    pub version: u32,
    pub schema_digest: String,
}

impl SchemaDescriptor {
    pub fn validate(&self) -> Result<()> {
        if !valid_schema_id(&self.schema_id)
            || self.version == 0
            || !valid_digest(&self.schema_digest)
        {
            return Err(Error::Invalid("schema descriptor is malformed".into()));
        }
        Ok(())
    }
}

/// Caller-owned registry of immutable schema identities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchemaRegistry {
    records: BTreeMap<(String, u32), SchemaDescriptor>,
}

impl SchemaRegistry {
    pub fn register(&mut self, descriptor: SchemaDescriptor) -> Result<()> {
        descriptor.validate()?;
        let key = (descriptor.schema_id.clone(), descriptor.version);
        if self.records.contains_key(&key) {
            return Err(Error::Rejected("schema identity already registered".into()));
        }
        self.records.insert(key, descriptor);
        Ok(())
    }

    pub fn get(&self, schema_id: &str, version: u32) -> Option<&SchemaDescriptor> {
        self.records.get(&(schema_id.to_owned(), version))
    }

    /// Requires an exact schema ID, version, and digest match.
    pub fn require(
        &self,
        schema_id: &str,
        version: u32,
        schema_digest: &str,
    ) -> Result<&SchemaDescriptor> {
        if !valid_schema_id(schema_id) || version == 0 || !valid_digest(schema_digest) {
            return Err(Error::Invalid("schema requirement is malformed".into()));
        }
        let descriptor = self
            .get(schema_id, version)
            .ok_or_else(|| Error::Quarantined("schema identity is unavailable".into()))?;
        if descriptor.schema_digest != schema_digest {
            return Err(Error::Rejected("schema digest binding mismatch".into()));
        }
        Ok(descriptor)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> SchemaDescriptor {
        SchemaDescriptor {
            schema_id: "proposal-v1".into(),
            version: 1,
            schema_digest: "a".repeat(64),
        }
    }

    #[test]
    fn exact_schema_identity_is_required() {
        let item = descriptor();
        let mut registry = SchemaRegistry::default();
        registry.register(item.clone()).expect("register");
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry
                .require("proposal-v1", 1, &item.schema_digest)
                .expect("require"),
            &item
        );
        assert!(registry.require("proposal-v1", 1, &"b".repeat(64)).is_err());
        assert!(registry
            .require("proposal-v1", 2, &item.schema_digest)
            .is_err());
    }

    #[test]
    fn malformed_and_duplicate_descriptors_fail_closed() {
        let mut registry = SchemaRegistry::default();
        let mut malformed = descriptor();
        malformed.version = 0;
        assert!(registry.register(malformed).is_err());
        let item = descriptor();
        registry.register(item.clone()).expect("register");
        assert!(registry.register(item).is_err());
        assert!(registry
            .register(SchemaDescriptor {
                schema_id: "proposal v1".into(),
                version: 2,
                schema_digest: "b".repeat(64),
            })
            .is_err());
    }
}
