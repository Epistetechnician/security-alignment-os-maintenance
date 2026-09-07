//! Meet-only claim aggregation and digest-only release packets.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! Claim composition can preserve or narrow a claim ceiling, never widen it.
//! The records contain digests and aggregate labels only; raw evidence and
//! private custody locators are excluded by construction.

use crate::{digest, valid_digest, Error, Result, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_TEXT_LEN: usize = 256;

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_LEN
        && !value.chars().any(|character| character.is_control())
}

fn valid_text_set(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| valid_text(value))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimEnvelope {
    pub claim_id: String,
    pub state_slice: String,
    pub claim_ceiling: String,
    pub guarantees: BTreeSet<String>,
    pub assumptions: BTreeSet<String>,
    pub excludes: BTreeSet<String>,
    pub evidence_digests: BTreeSet<String>,
    pub valid_until: u64,
}

impl ClaimEnvelope {
    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.claim_id)
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.claim_ceiling)
            || self.valid_until == 0
            || !valid_text_set(&self.guarantees)
            || !valid_text_set(&self.assumptions)
            || !valid_text_set(&self.excludes)
            || self
                .guarantees
                .intersection(&self.excludes)
                .next()
                .is_some()
            || self
                .evidence_digests
                .iter()
                .any(|digest| !valid_digest(digest))
        {
            return Err(Error::Invalid("claim envelope is malformed".into()));
        }
        Ok(())
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        self.validate().is_ok() && self.valid_until > now
    }

    /// Composes two envelopes by meeting guarantees and ceilings while
    /// unioning assumptions, exclusions, and evidence references.
    pub fn meet(&self, other: &Self) -> Result<Self> {
        self.validate()?;
        other.validate()?;
        if self.state_slice != other.state_slice || self.claim_ceiling != other.claim_ceiling {
            return Err(Error::Rejected(
                "claim envelopes have incompatible state or ceiling".into(),
            ));
        }
        let guarantees = self
            .guarantees
            .intersection(&other.guarantees)
            .cloned()
            .collect();
        let assumptions = self
            .assumptions
            .union(&other.assumptions)
            .cloned()
            .collect();
        let excludes = self.excludes.union(&other.excludes).cloned().collect();
        let evidence_digests = self
            .evidence_digests
            .union(&other.evidence_digests)
            .cloned()
            .collect();
        let mut result = Self {
            claim_id: String::new(),
            state_slice: self.state_slice.clone(),
            claim_ceiling: self.claim_ceiling.clone(),
            guarantees,
            assumptions,
            excludes,
            evidence_digests,
            valid_until: self.valid_until.min(other.valid_until),
        };
        result.claim_id = digest(&(
            "claim-meet-v1",
            &result.state_slice,
            &result.claim_ceiling,
            &result.guarantees,
            &result.assumptions,
            &result.excludes,
            &result.evidence_digests,
            result.valid_until,
        ))?;
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregateReleasePacket {
    pub packet_id: String,
    pub state_slice: String,
    pub claim_ceiling: String,
    pub claim_ids: BTreeSet<String>,
    pub evidence_digests: BTreeSet<String>,
    pub generated_at: u64,
    /// Always false in this local aggregate-only contract.
    pub raw_payload_included: bool,
}

impl AggregateReleasePacket {
    pub fn from_envelopes(
        packet_id: impl Into<String>,
        envelopes: &[ClaimEnvelope],
        generated_at: u64,
    ) -> Result<Self> {
        if envelopes.is_empty() {
            return Err(Error::Invalid("release packet needs one claim".into()));
        }
        for envelope in envelopes {
            envelope.validate()?;
        }
        let state_slice = envelopes[0].state_slice.clone();
        let claim_ceiling = envelopes[0].claim_ceiling.clone();
        if envelopes.iter().any(|envelope| {
            envelope.state_slice != state_slice || envelope.claim_ceiling != claim_ceiling
        }) {
            return Err(Error::Rejected(
                "release packet claims have incompatible state or ceiling".into(),
            ));
        }
        let packet = Self {
            packet_id: packet_id.into(),
            state_slice,
            claim_ceiling,
            claim_ids: envelopes
                .iter()
                .map(|envelope| envelope.claim_id.clone())
                .collect(),
            evidence_digests: envelopes
                .iter()
                .flat_map(|envelope| envelope.evidence_digests.iter().cloned())
                .collect(),
            generated_at,
            raw_payload_included: false,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.packet_id)
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.claim_ceiling)
            || self.claim_ids.is_empty()
            || self.claim_ids.iter().any(|id| !valid_text(id))
            || self
                .evidence_digests
                .iter()
                .any(|digest| !valid_digest(digest))
            || self.raw_payload_included
        {
            return Err(Error::Invalid(
                "aggregate release packet is malformed".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(id: &str, guarantee: &str, evidence: char) -> ClaimEnvelope {
        ClaimEnvelope {
            claim_id: id.into(),
            state_slice: STATE_SLICE.into(),
            claim_ceiling: "LocalControlOnly".into(),
            guarantees: [guarantee.into()].into_iter().collect(),
            assumptions: ["caller-clock".into()].into_iter().collect(),
            excludes: ["alignment".into()].into_iter().collect(),
            evidence_digests: [std::iter::repeat(evidence).take(64).collect()]
                .into_iter()
                .collect(),
            valid_until: 100,
        }
    }

    #[test]
    fn meet_only_composition_narrows_guarantees_and_expiry() {
        let left = envelope("left", "PolicyCompliance", 'a');
        let right = envelope("right", "RuntimeBound", 'b');
        let result = left.meet(&right).expect("meet");
        assert!(result.guarantees.is_empty());
        assert_eq!(result.valid_until, 100);
        assert_eq!(result.evidence_digests.len(), 2);
        assert!(result.is_valid_at(99));
    }

    #[test]
    fn incompatible_or_contradictory_claims_fail_closed() {
        let mut incompatible = envelope("other", "PolicyCompliance", 'a');
        incompatible.claim_ceiling = "BroaderClaim".into();
        assert!(envelope("left", "PolicyCompliance", 'a')
            .meet(&incompatible)
            .is_err());
        let mut contradictory = envelope("contradictory", "PolicyCompliance", 'a');
        contradictory.excludes.clear();
        contradictory.guarantees.insert("PolicyCompliance".into());
        contradictory.excludes.insert("PolicyCompliance".into());
        assert!(contradictory.validate().is_err());
    }

    #[test]
    fn aggregate_packet_excludes_raw_payloads_and_is_digest_bound() {
        let left = envelope("left", "PolicyCompliance", 'a');
        let right = envelope("right", "RuntimeBound", 'b');
        let packet =
            AggregateReleasePacket::from_envelopes("packet-1", &[left, right], 50).expect("packet");
        let first = packet.digest().expect("digest");
        assert_eq!(first, packet.digest().expect("digest"));
        assert!(!packet.raw_payload_included);
        let mut invalid = packet;
        invalid.raw_payload_included = true;
        assert!(invalid.validate().is_err());
    }
}
