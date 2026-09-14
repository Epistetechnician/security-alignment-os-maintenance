//! Canonical schema and digest-only identity for the fresh protocol packet.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//! This module validates synthetic local fixture metadata. It does not load a
//! model, retain scientific traces, contact a provider, or authorize effects.

use crate::{canonical_bytes, digest, Error, Result, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub const PACKET_SCHEMA: &str = "security-alignment-os-fresh-protocol-packet-v1";
pub const PROTOCOL_ID: &str = "fresh-207-552-v1";
pub const GENERATOR_REVISION: &str = "protocol-packet-generator-v1";
pub const SOURCE: &str = "local-synthetic-fresh-document-generator";
pub const AUTHOR: &str = "local-synthetic-author-assertion";
pub const CREATED_ON: &str = "2026-09-14";
pub const DOCUMENTS_PER_SPLIT: usize = 69;
pub const FAMILIES_PER_DOCUMENT: usize = 8;
pub const EXPECTED_DOCUMENTS: usize = DOCUMENTS_PER_SPLIT * 3;
pub const EXPECTED_FAMILIES_PER_SPLIT: usize = DOCUMENTS_PER_SPLIT * FAMILIES_PER_DOCUMENT;

const SPLITS: [&str; 3] = ["fit", "tune", "assessment"];

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentHeader {
    pub schema: String,
    pub state_slice: String,
    pub protocol_id: String,
    pub document_id: String,
    pub source: String,
    pub revision: String,
    pub split: String,
    pub author: String,
    pub families: Vec<String>,
    pub fresh_nonce: String,
}

impl DocumentHeader {
    pub fn from_canonical_line(bytes: &[u8]) -> Result<Self> {
        let header: Self = serde_json::from_slice(bytes)?;
        if canonical_bytes(&header)? != bytes {
            return Err(Error::Invalid(
                "fresh packet document header is not canonical".into(),
            ));
        }
        Ok(header)
    }

    pub fn validate_for_entry(&self, entry: &ManifestEntry) -> Result<()> {
        if self.schema != PACKET_SCHEMA
            || self.state_slice != STATE_SLICE
            || self.protocol_id != PROTOCOL_ID
            || self.source != entry.source
            || self.revision != entry.revision
            || self.split != entry.split
            || self.author != entry.author
            || self.families != entry.families
            || self.document_id != document_id_from_path(&entry.path)?
            || self.fresh_nonce
                != digest(&(
                    PROTOCOL_ID,
                    &self.split,
                    document_index(&entry.path)?,
                    &self.families,
                ))?
        {
            return Err(Error::Invalid(format!(
                "fresh packet document header mismatch for {}",
                entry.path
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub source: String,
    pub revision: String,
    pub split: String,
    pub author: String,
    pub path: String,
    pub sha256: String,
    pub families: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub state_slice: String,
    pub protocol_id: String,
    pub created_on: String,
    pub document_count: usize,
    pub families_per_document: usize,
    pub documents: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if canonical_bytes(&manifest)? != bytes {
            return Err(Error::Invalid(
                "fresh packet manifest is not canonical".into(),
            ));
        }
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != PACKET_SCHEMA
            || self.state_slice != STATE_SLICE
            || self.protocol_id != PROTOCOL_ID
            || self.created_on != CREATED_ON
            || self.document_count != EXPECTED_DOCUMENTS
            || self.families_per_document != FAMILIES_PER_DOCUMENT
            || self.documents.len() != EXPECTED_DOCUMENTS
        {
            return Err(Error::Invalid(
                "fresh packet manifest identity is invalid".into(),
            ));
        }

        let mut paths = BTreeSet::new();
        let mut split_documents = BTreeMap::<&str, usize>::new();
        let mut split_families = BTreeMap::<&str, BTreeSet<&str>>::new();
        for entry in &self.documents {
            if entry.source != SOURCE
                || entry.revision != GENERATOR_REVISION
                || entry.author != AUTHOR
                || !SPLITS.contains(&entry.split.as_str())
                || !valid_digest(&entry.sha256)
                || entry.families.len() != FAMILIES_PER_DOCUMENT
                || entry.families.iter().any(|family| !valid_text(family))
                || entry.families.iter().collect::<BTreeSet<_>>().len() != FAMILIES_PER_DOCUMENT
                || !paths.insert(entry.path.clone())
            {
                return Err(Error::Invalid(
                    "fresh packet manifest entry identity is invalid".into(),
                ));
            }
            let relative_path = Path::new(&entry.path);
            if relative_path.is_absolute()
                || relative_path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
                || !entry.path.ends_with(".md")
            {
                return Err(Error::Invalid(
                    "fresh packet manifest path is unsafe".into(),
                ));
            }
            let index = document_index(&entry.path)?;
            let expected_path = format!("{}/{}-{:03}.md", entry.split, entry.split, index + 1);
            if entry.path != expected_path {
                return Err(Error::Invalid(
                    "fresh packet manifest path does not match its split".into(),
                ));
            }
            *split_documents.entry(entry.split.as_str()).or_default() += 1;
            let families = split_families.entry(entry.split.as_str()).or_default();
            for family in &entry.families {
                if !families.insert(family.as_str()) {
                    return Err(Error::Invalid(format!(
                        "duplicate fresh packet family {} in {}",
                        family, entry.split
                    )));
                }
            }
        }
        for split in SPLITS {
            if split_documents.get(split).copied().unwrap_or_default() != DOCUMENTS_PER_SPLIT
                || split_families.get(split).map_or(0, BTreeSet::len) != EXPECTED_FAMILIES_PER_SPLIT
            {
                return Err(Error::Invalid(format!(
                    "fresh packet split {split} has invalid counts"
                )));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        digest(self)
    }

    pub fn digest_bytes(bytes: &[u8]) -> Result<String> {
        Self::from_canonical_bytes(bytes)?;
        Ok(crate::digest_bytes(bytes))
    }
}

pub fn document_id_from_path(path: &str) -> Result<String> {
    Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .map(Into::into)
        .ok_or_else(|| Error::Invalid("fresh packet path has no document ID".into()))
}

pub fn document_index(path: &str) -> Result<usize> {
    let name = document_id_from_path(path)?;
    let suffix = name
        .rsplit('-')
        .next()
        .ok_or_else(|| Error::Invalid("fresh packet document ID has no index".into()))?;
    let index = suffix
        .parse::<usize>()
        .map_err(|_| Error::Invalid("fresh packet document index is invalid".into()))?;
    let index = index
        .checked_sub(1)
        .ok_or_else(|| Error::Invalid("fresh packet document index starts at 1".into()))?;
    if index >= DOCUMENTS_PER_SPLIT {
        return Err(Error::Invalid(
            "fresh packet document index is out of range".into(),
        ));
    }
    Ok(index)
}
