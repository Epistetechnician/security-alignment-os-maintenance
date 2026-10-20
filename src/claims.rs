//! Meet-only claim aggregation and digest-only release packets.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! Claim composition can preserve or narrow a claim ceiling, never widen it.
//! The records contain digests and aggregate labels only; raw evidence and
//! private custody locators are excluded by construction.

use crate::{digest, valid_digest, Error, EvidenceRegistry, Result, STATE_SLICE};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

/// Local evidence references required to assemble one release claim.
///
/// `subject_digest` binds each accepted evidence record to the exact subject
/// bytes under review. The role identities in those records remain local
/// caller assertions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimEvidenceBinding {
    pub claim_id: String,
    pub subject_digest: String,
    pub evidence_ids: BTreeSet<String>,
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
    /// Commits each claim ID to its complete canonical envelope.
    pub claim_digests: BTreeMap<String, String>,
    /// Preserves each claim's evidence references and exact subject binding.
    pub claim_evidence_digests: BTreeMap<String, BTreeSet<String>>,
    pub claim_subject_digests: BTreeMap<String, String>,
    pub evidence_digests: BTreeSet<String>,
    pub generated_at: u64,
    /// Always false in this local aggregate-only contract.
    pub raw_payload_included: bool,
}

impl AggregateReleasePacket {
    pub fn from_envelopes(
        packet_id: impl Into<String>,
        envelopes: &[ClaimEnvelope],
        bindings: &[ClaimEvidenceBinding],
        evidence: &EvidenceRegistry,
        generated_at: u64,
    ) -> Result<Self> {
        if envelopes.is_empty() || generated_at == 0 {
            return Err(Error::Invalid("release packet needs one claim".into()));
        }
        for envelope in envelopes {
            envelope.validate()?;
            if !envelope.is_valid_at(generated_at) {
                return Err(Error::Rejected(
                    "release claim is expired at packet creation".into(),
                ));
            }
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
        if bindings.len() != envelopes.len() {
            return Err(Error::Rejected(
                "release claims and evidence bindings do not match".into(),
            ));
        }

        let mut envelope_by_id = BTreeMap::new();
        for envelope in envelopes {
            if envelope_by_id
                .insert(envelope.claim_id.as_str(), envelope)
                .is_some()
            {
                return Err(Error::Rejected("duplicate release claim identifier".into()));
            }
        }

        let mut claim_digests = BTreeMap::new();
        let mut claim_evidence_digests = BTreeMap::new();
        let mut claim_subject_digests = BTreeMap::new();
        let mut evidence_digests = BTreeSet::new();
        for binding in bindings {
            let envelope = envelope_by_id
                .get(binding.claim_id.as_str())
                .ok_or_else(|| Error::Rejected("unmatched claim evidence binding".into()))?;
            if !valid_digest(&binding.subject_digest) || binding.evidence_ids.is_empty() {
                return Err(Error::Invalid("claim evidence binding is malformed".into()));
            }

            let mut bound_digests = BTreeSet::new();
            for evidence_id in &binding.evidence_ids {
                if !valid_text(evidence_id) {
                    return Err(Error::Invalid(
                        "claim evidence identifier is malformed".into(),
                    ));
                }
                bound_digests.insert(evidence.accepted_digest_for(
                    evidence_id,
                    generated_at,
                    &binding.subject_digest,
                    envelope.valid_until,
                )?);
            }
            if bound_digests != envelope.evidence_digests {
                return Err(Error::Rejected(
                    "claim evidence references do not match accepted evidence".into(),
                ));
            }
            let claim_id = envelope.claim_id.clone();
            claim_digests.insert(claim_id.clone(), digest(envelope)?);
            claim_evidence_digests.insert(claim_id.clone(), bound_digests.clone());
            claim_subject_digests.insert(claim_id, binding.subject_digest.clone());
            evidence_digests.extend(bound_digests);
        }

        let packet = Self {
            packet_id: packet_id.into(),
            state_slice,
            claim_ceiling,
            claim_ids: envelope_by_id.keys().map(|id| (*id).to_string()).collect(),
            claim_digests,
            claim_evidence_digests,
            claim_subject_digests,
            evidence_digests,
            generated_at,
            raw_payload_included: false,
        };
        packet.validate()?;
        packet.validate_current(envelopes, evidence, generated_at)?;
        Ok(packet)
    }

    /// Checks that packet commitments still match the supplied claims and
    /// currently accepted evidence at `now`.
    pub fn validate_current(
        &self,
        envelopes: &[ClaimEnvelope],
        evidence: &EvidenceRegistry,
        now: u64,
    ) -> Result<()> {
        self.validate_claims(envelopes)?;
        if now < self.generated_at {
            return Err(Error::Rejected("release packet is from the future".into()));
        }
        for envelope in envelopes {
            if !envelope.is_valid_at(now) {
                return Err(Error::Rejected("release claim is expired".into()));
            }
            let subject = self
                .claim_subject_digests
                .get(&envelope.claim_id)
                .ok_or_else(|| Error::Invalid("release claim subject is missing".into()))?;
            if envelope.evidence_digests.iter().any(|evidence_digest| {
                !evidence.has_valid_digest_for_subject(evidence_digest, now, subject)
            }) {
                return Err(Error::Rejected(
                    "release packet evidence is revoked, expired, or mismatched".into(),
                ));
            }
        }
        Ok(())
    }

    /// Verifies claim content commitments without consulting evidence status.
    /// This lets durable release snapshots detect structural tampering on
    /// load, then revalidate evidence against the current registry separately.
    pub fn validate_claims(&self, envelopes: &[ClaimEnvelope]) -> Result<()> {
        self.validate()?;
        if envelopes.len() != self.claim_ids.len() {
            return Err(Error::Rejected(
                "release packet claim set is inconsistent".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for envelope in envelopes {
            envelope.validate()?;
            if envelope.state_slice != self.state_slice
                || envelope.claim_ceiling != self.claim_ceiling
                || !seen.insert(envelope.claim_id.as_str())
                || self.claim_digests.get(&envelope.claim_id) != Some(&digest(envelope)?)
                || self.claim_evidence_digests.get(&envelope.claim_id)
                    != Some(&envelope.evidence_digests)
            {
                return Err(Error::Rejected(
                    "release packet claim commitment is stale or mismatched".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_text(&self.packet_id)
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.claim_ceiling)
            || self.claim_ids.is_empty()
            || self.claim_ids.iter().any(|id| !valid_text(id))
            || self.claim_digests.keys().cloned().collect::<BTreeSet<_>>() != self.claim_ids
            || self
                .claim_digests
                .values()
                .any(|claim_digest| !valid_digest(claim_digest))
            || self
                .claim_evidence_digests
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != self.claim_ids
            || self
                .claim_subject_digests
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != self.claim_ids
            || self
                .claim_subject_digests
                .values()
                .any(|subject| !valid_digest(subject))
            || self.claim_evidence_digests.values().any(BTreeSet::is_empty)
            || self
                .claim_evidence_digests
                .values()
                .flat_map(|digests| digests.iter().cloned())
                .collect::<BTreeSet<_>>()
                != self.evidence_digests
            || self
                .evidence_digests
                .iter()
                .any(|digest| !valid_digest(digest))
            || self.generated_at == 0
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

    fn accepted_evidence(subject_digest: &str, evidence_id: &str) -> EvidenceRegistry {
        let mut registry = EvidenceRegistry::default();
        registry
            .insert(crate::Evidence {
                id: evidence_id.into(),
                source_digest: subject_digest.into(),
                operator_id: "operator-local".into(),
                validator_id: "validator-local".into(),
                reviewer_id: String::new(),
                valid_until: 100,
                accepted: false,
                revoked: false,
            })
            .expect("insert held evidence");
        registry
            .accept(evidence_id, "reviewer-local")
            .expect("accept fixture evidence");
        registry
    }

    fn bound_envelope(
        id: &str,
        registry: &EvidenceRegistry,
    ) -> (ClaimEnvelope, ClaimEvidenceBinding) {
        let subject = "a".repeat(64);
        let evidence_id = "evidence-1";
        let evidence_digest = registry
            .accepted_digest_for(evidence_id, 50, &subject, 90)
            .expect("current subject-bound evidence");
        let envelope = ClaimEnvelope {
            claim_id: id.into(),
            state_slice: STATE_SLICE.into(),
            claim_ceiling: "LocalControlOnly".into(),
            guarantees: ["PolicyCompliance".into()].into_iter().collect(),
            assumptions: ["local-role-assertions".into()].into_iter().collect(),
            excludes: ["alignment".into()].into_iter().collect(),
            evidence_digests: [evidence_digest].into_iter().collect(),
            valid_until: 90,
        };
        let binding = ClaimEvidenceBinding {
            claim_id: id.into(),
            subject_digest: subject,
            evidence_ids: [evidence_id.into()].into_iter().collect(),
        };
        (envelope, binding)
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
        let evidence = accepted_evidence(&"a".repeat(64), "evidence-1");
        let (verified, binding) = bound_envelope("verified", &evidence);
        let packet = AggregateReleasePacket::from_envelopes(
            "packet-1",
            std::slice::from_ref(&verified),
            &[binding],
            &evidence,
            50,
        )
        .expect("packet");
        let first = packet.digest().expect("digest");
        assert_eq!(first, packet.digest().expect("digest"));
        assert!(!packet.raw_payload_included);
        packet
            .validate_current(std::slice::from_ref(&verified), &evidence, 51)
            .expect("packet evidence remains current");

        let mut revoked = evidence.clone();
        revoked.revoke("evidence-1").expect("revoke evidence");
        assert!(packet.validate_current(&[verified], &revoked, 51).is_err());

        let mut invalid = packet;
        invalid.raw_payload_included = true;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn evidence_bound_packet_rejects_mismatch_expiry_and_claim_tampering() {
        let evidence = accepted_evidence(&"a".repeat(64), "evidence-1");
        let (envelope, binding) = bound_envelope("verified", &evidence);
        let mut wrong_subject = binding.clone();
        wrong_subject.subject_digest = "b".repeat(64);
        assert!(AggregateReleasePacket::from_envelopes(
            "wrong-subject",
            std::slice::from_ref(&envelope),
            &[wrong_subject],
            &evidence,
            50,
        )
        .is_err());

        let packet = AggregateReleasePacket::from_envelopes(
            "packet-1",
            std::slice::from_ref(&envelope),
            &[binding],
            &evidence,
            50,
        )
        .expect("packet");
        assert!(packet
            .validate_current(std::slice::from_ref(&envelope), &evidence, 90)
            .is_err());

        let mut changed_claim = envelope;
        changed_claim.guarantees.clear();
        assert!(packet
            .validate_current(&[changed_claim], &evidence, 51)
            .is_err());
    }

    #[test]
    fn packet_creation_rejects_unaccepted_or_short_lived_evidence() {
        let accepted = accepted_evidence(&"a".repeat(64), "evidence-1");
        let (envelope, binding) = bound_envelope("verified", &accepted);

        let mut held = EvidenceRegistry::default();
        held.insert(crate::Evidence {
            id: "evidence-1".into(),
            source_digest: "a".repeat(64),
            operator_id: "operator-local".into(),
            validator_id: "validator-local".into(),
            reviewer_id: String::new(),
            valid_until: 100,
            accepted: false,
            revoked: false,
        })
        .expect("held evidence");
        assert!(AggregateReleasePacket::from_envelopes(
            "held-evidence",
            std::slice::from_ref(&envelope),
            std::slice::from_ref(&binding),
            &held,
            50,
        )
        .is_err());

        let short_record = crate::Evidence {
            id: "evidence-1".into(),
            source_digest: "a".repeat(64),
            operator_id: "operator-local".into(),
            validator_id: "validator-local".into(),
            reviewer_id: "reviewer-local".into(),
            valid_until: 80,
            accepted: true,
            revoked: false,
        };
        let mut short_lived = EvidenceRegistry::default();
        short_lived
            .insert(short_record.clone())
            .expect("short-lived evidence");
        let mut long_claim = envelope;
        long_claim.evidence_digests = [digest(&short_record).expect("short evidence digest")]
            .into_iter()
            .collect();
        assert!(AggregateReleasePacket::from_envelopes(
            "short-evidence",
            &[long_claim],
            &[binding],
            &short_lived,
            50,
        )
        .is_err());
    }
}
