//! Shadow/canary release records; no model promotion or deployment.
//!
//! State slice: `security-alignment-os-foundation-v1`.

use crate::claims::{AggregateReleasePacket, ClaimEnvelope};
use crate::persistence::{read_regular_snapshot, recover_atomic_snapshot, save_atomic_snapshot};
use crate::{canonical_bytes, digest, valid_digest, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateUpdate {
    pub candidate_id: String,
    pub base_digest: String,
    pub candidate_digest: String,
    pub rollback_digest: String,
    pub evidence_digest: String,
}

impl CandidateUpdate {
    pub fn validate(&self) -> Result<()> {
        if self.candidate_id.is_empty()
            || !valid_digest(&self.base_digest)
            || !valid_digest(&self.candidate_digest)
            || !valid_digest(&self.rollback_digest)
            || !valid_digest(&self.evidence_digest)
            || self.base_digest == self.candidate_digest
            || self.base_digest != self.rollback_digest
        {
            return Err(Error::Invalid("invalid immutable-base candidate".into()));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(&(
            &self.candidate_id,
            &self.base_digest,
            &self.candidate_digest,
            &self.rollback_digest,
            &self.evidence_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReleaseState {
    Shadow,
    Canary,
    ReleasedLocal,
    Frozen,
}

/// Aggregate claim material retained so release evidence can be rechecked
/// after the registry is reloaded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseEvidencePacket {
    pub packet: AggregateReleasePacket,
    pub envelopes: Vec<ClaimEnvelope>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseRegistry {
    records: BTreeMap<String, (CandidateUpdate, ReleaseState)>,
    used_evidence: BTreeMap<String, BTreeSet<String>>,
    packets: BTreeMap<String, Vec<ReleaseEvidencePacket>>,
}

impl ReleaseRegistry {
    pub fn validate(&self) -> Result<()> {
        if self.records.len() != self.used_evidence.len()
            || self.records.len() != self.packets.len()
        {
            return Err(Error::Invalid(
                "release evidence indexes are inconsistent".into(),
            ));
        }
        for (id, (candidate, state)) in &self.records {
            if id != &candidate.candidate_id {
                return Err(Error::Invalid("release candidate key mismatch".into()));
            }
            candidate.validate()?;
            let used = self
                .used_evidence
                .get(id)
                .ok_or_else(|| Error::Invalid("release evidence record is missing".into()))?;
            let packets = self
                .packets
                .get(id)
                .ok_or_else(|| Error::Invalid("release packet records are missing".into()))?;
            let expected_packet_count = match state {
                ReleaseState::Shadow => 0,
                ReleaseState::Canary => 1,
                ReleaseState::ReleasedLocal => 2,
                ReleaseState::Frozen if packets.len() <= 2 => packets.len(),
                ReleaseState::Frozen => {
                    return Err(Error::Invalid(
                        "frozen release has too many evidence packets".into(),
                    ))
                }
            };
            if packets.len() != expected_packet_count {
                return Err(Error::Invalid(
                    "release state and packet count are inconsistent".into(),
                ));
            }
            let mut packet_digests = BTreeSet::new();
            for packet in packets {
                packet.packet.validate_claims(&packet.envelopes)?;
                let packet_digest = packet.packet.digest()?;
                if !packet_digests.insert(packet_digest) {
                    return Err(Error::Invalid("release packet was reused".into()));
                }
            }
            if &packet_digests != used {
                return Err(Error::Invalid(
                    "release packet digest index is inconsistent".into(),
                ));
            }
            if let Some(packet) = packets.first() {
                if packet.packet.digest()? != candidate.evidence_digest {
                    return Err(Error::Invalid(
                        "initial release packet does not match candidate evidence".into(),
                    ));
                }
            }
            if !used.contains(&candidate.evidence_digest)
                && !matches!(state, ReleaseState::Shadow | ReleaseState::Frozen)
            {
                return Err(Error::Invalid(
                    "release state lacks initial candidate evidence".into(),
                ));
            }
            match state {
                ReleaseState::Shadow if !used.is_empty() => {
                    return Err(Error::Invalid("shadow release has phase evidence".into()))
                }
                ReleaseState::Canary if used.len() != 1 => {
                    return Err(Error::Invalid(
                        "canary release evidence count is invalid".into(),
                    ))
                }
                ReleaseState::ReleasedLocal if used.len() != 2 => {
                    return Err(Error::Invalid(
                        "local release requires distinct phase evidence".into(),
                    ))
                }
                ReleaseState::Frozen if used.len() > 2 => {
                    return Err(Error::Invalid(
                        "frozen release evidence count is invalid".into(),
                    ))
                }
                _ => {}
            }
            if used.iter().any(|evidence| !valid_digest(evidence)) {
                return Err(Error::Invalid(
                    "release evidence digest is malformed".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn propose(&mut self, candidate: CandidateUpdate) -> Result<()> {
        candidate.validate()?;
        if self.records.contains_key(&candidate.candidate_id) {
            return Err(Error::Rejected("candidate identity already exists".into()));
        }
        let candidate_id = candidate.candidate_id.clone();
        self.records
            .insert(candidate_id.clone(), (candidate, ReleaseState::Shadow));
        if !self.records.contains_key(&candidate_id) {
            return Err(Error::Invalid("candidate was not recorded".into()));
        }
        self.used_evidence
            .insert(candidate_id.clone(), BTreeSet::new());
        self.packets.insert(candidate_id, Vec::new());
        self.validate()?;
        Ok(())
    }
    pub fn state(&self, id: &str) -> Option<ReleaseState> {
        self.records.get(id).map(|(_, state)| *state)
    }
    /// Advances local release metadata only when a current evidence-bound
    /// packet validates against the supplied claim envelopes and registry.
    pub fn advance_with_packet(
        &mut self,
        id: &str,
        packet: &AggregateReleasePacket,
        envelopes: &[ClaimEnvelope],
        evidence: &crate::EvidenceRegistry,
        now: u64,
    ) -> Result<()> {
        packet.validate_current(envelopes, evidence, now)?;
        let packet_digest = packet.digest()?;
        let mut staged = self.clone();
        let packets = staged
            .packets
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("candidate packet state missing".into()))?;
        packets.push(ReleaseEvidencePacket {
            packet: packet.clone(),
            envelopes: envelopes.to_vec(),
        });
        staged.advance_digest(id, &packet_digest)?;
        *self = staged;
        Ok(())
    }

    fn advance_digest(&mut self, id: &str, evidence_digest: &str) -> Result<()> {
        let (candidate, state) = self
            .records
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("unknown candidate".into()))?;
        if candidate.evidence_digest != evidence_digest
            && (*state != ReleaseState::Canary
                || !valid_digest(evidence_digest)
                || evidence_digest == candidate.evidence_digest)
        {
            return Err(Error::Rejected("phase evidence mismatch".into()));
        }
        let next = match state {
            ReleaseState::Shadow => ReleaseState::Canary,
            ReleaseState::Canary => ReleaseState::ReleasedLocal,
            _ => return Err(Error::Rejected("terminal release state".into())),
        };
        let used = self
            .used_evidence
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("candidate evidence state missing".into()))?;
        if !used.insert(evidence_digest.into()) {
            return Err(Error::Rejected("phase evidence already used".into()));
        }
        *state = next;
        self.validate()?;
        Ok(())
    }
    pub fn freeze(&mut self, id: &str) -> Result<()> {
        let (_, state) = self
            .records
            .get_mut(id)
            .ok_or_else(|| Error::Invalid("unknown candidate".into()))?;
        if *state == ReleaseState::Frozen {
            return Err(Error::Rejected("candidate is already frozen".into()));
        }
        *state = ReleaseState::Frozen;
        self.validate()?;
        Ok(())
    }

    /// Revalidates retained packets and moves stale active release metadata to
    /// terminal `Frozen` state. The caller persists the returned registry with
    /// `save` or uses `revalidate_and_save` for an atomic local update.
    pub fn revalidate_evidence(
        &mut self,
        evidence: &crate::EvidenceRegistry,
        now: u64,
    ) -> Result<Vec<String>> {
        self.validate()?;
        let mut staged = self.clone();
        let mut frozen = Vec::new();
        for (id, (_, state)) in &mut staged.records {
            if matches!(state, ReleaseState::Shadow | ReleaseState::Frozen) {
                continue;
            }
            let packets = staged
                .packets
                .get(id)
                .ok_or_else(|| Error::Invalid("release packet records are missing".into()))?;
            if packets.iter().any(|record| {
                record
                    .packet
                    .validate_current(&record.envelopes, evidence, now)
                    .is_err()
            }) {
                *state = ReleaseState::Frozen;
                frozen.push(id.clone());
            }
        }
        staged.validate()?;
        *self = staged;
        Ok(frozen)
    }

    /// Loads a release registry, revalidates all active evidence packets, and
    /// atomically persists any terminal freezes before returning their IDs.
    pub fn revalidate_and_save(
        path: &Path,
        evidence: &crate::EvidenceRegistry,
        now: u64,
    ) -> Result<Vec<String>> {
        let mut registry = Self::load(path)?;
        let frozen = registry.revalidate_evidence(evidence, now)?;
        registry.save(path)?;
        Ok(frozen)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        save_atomic_snapshot(path, &canonical_bytes(self)?, "release registry")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_snapshot(path)?;
        let registry: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&registry)? != bytes {
            return Err(Error::Journal(
                "release bytes are not canonical JSON".into(),
            ));
        }
        registry.validate()?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        recover_atomic_snapshot(path, "release registry", Self::load)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> CandidateUpdate {
        CandidateUpdate {
            candidate_id: "candidate-1".into(),
            base_digest: "a".repeat(64),
            candidate_digest: "b".repeat(64),
            rollback_digest: "a".repeat(64),
            evidence_digest: "c".repeat(64),
        }
    }

    #[test]
    fn lifecycle_evidence_cardinality_is_validated() {
        let mut registry = ReleaseRegistry::default();
        registry.propose(candidate()).expect("propose");
        registry.freeze("candidate-1").expect("freeze");
        registry.validate().expect("frozen validation");
        assert!(registry
            .advance_with_packet(
                "candidate-1",
                &AggregateReleasePacket {
                    packet_id: "unverified".into(),
                    state_slice: crate::STATE_SLICE.into(),
                    claim_ceiling: "local".into(),
                    claim_ids: ["claim".into()].into_iter().collect(),
                    claim_digests: [("claim".into(), "a".repeat(64))].into_iter().collect(),
                    claim_evidence_digests: [(
                        "claim".into(),
                        ["b".repeat(64)].into_iter().collect()
                    )]
                    .into_iter()
                    .collect(),
                    claim_subject_digests: [("claim".into(), "c".repeat(64))].into_iter().collect(),
                    evidence_digests: ["b".repeat(64)].into_iter().collect(),
                    generated_at: 1,
                    raw_payload_included: false,
                },
                &[],
                &crate::EvidenceRegistry::default(),
                1,
            )
            .is_err());
    }

    #[test]
    fn persistence_rejects_noncanonical_and_recovers_temp() {
        let mut registry = ReleaseRegistry::default();
        registry.propose(candidate()).expect("propose");
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("release.json");
        registry.save(&path).expect("save");
        assert_eq!(ReleaseRegistry::load(&path).expect("load"), registry);

        let mut bytes = std::fs::read(&path).expect("read");
        let tamper_index = bytes.len() - 2;
        bytes[tamper_index] = b' ';
        std::fs::write(&path, bytes).expect("tamper");
        assert!(ReleaseRegistry::load(&path).is_err());

        std::fs::write(
            path.with_extension("tmp"),
            canonical_bytes(&registry).expect("canonical"),
        )
        .expect("temporary snapshot");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(ReleaseRegistry::recover(&path).expect("recover"), registry);
    }
}
