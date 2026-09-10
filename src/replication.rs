//! Frozen replication packets and independently signed aggregate results.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module carries only exact identities, terminal labels, and digests. It
//! does not start a process, identify a host, retain raw files, or turn a
//! second local result into independent scientific or production evidence.

use crate::{canonical_bytes, digest, valid_digest, Error, Result, STATE_SLICE};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const PACKET_SCHEMA: &str = "security-alignment-os-replication-packet-v1";
const RESULT_SCHEMA: &str = "security-alignment-os-replication-result-v1";
const CLAIM_CEILING: &str = "ReplicatedBoundedMaintenanceExecution";
const SIGNATURE_LEN: usize = 64;
const KEY_LEN: usize = 32;
const MAX_TEXT_LEN: usize = 256;

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_LEN && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReplicationTerminal {
    Completed,
    RolledBack,
    Quarantined,
    Frozen,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReplicationDisposition {
    Matched,
    Quarantined,
}

/// Immutable packet exported by the original maintenance operator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenReplicationPacket {
    pub schema_version: String,
    pub state_slice: String,
    pub packet_id: String,
    pub source_revision_digest: String,
    pub toolchain_digest: String,
    pub configuration_digest: String,
    pub test_manifest_digest: String,
    pub request_digest: String,
    pub expected_terminal: ReplicationTerminal,
    pub expected_output_digest: Option<String>,
    pub expected_rollback_digest: String,
    pub expected_untouched_digest: String,
    pub expected_receipt_binding_digest: String,
    pub expected_recovery_frozen: bool,
    pub host_prerequisites: BTreeSet<String>,
    pub retention_until: u64,
    pub claim_ceiling: String,
    pub raw_payload_included: bool,
    pub packet_digest: String,
}

impl FrozenReplicationPacket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet_id: impl Into<String>,
        source_revision_digest: impl Into<String>,
        toolchain_digest: impl Into<String>,
        configuration_digest: impl Into<String>,
        test_manifest_digest: impl Into<String>,
        request_digest: impl Into<String>,
        expected_terminal: ReplicationTerminal,
        expected_output_digest: Option<String>,
        expected_rollback_digest: impl Into<String>,
        expected_untouched_digest: impl Into<String>,
        expected_receipt_binding_digest: impl Into<String>,
        expected_recovery_frozen: bool,
        host_prerequisites: BTreeSet<String>,
        retention_until: u64,
    ) -> Result<Self> {
        let mut packet = Self {
            schema_version: PACKET_SCHEMA.into(),
            state_slice: STATE_SLICE.into(),
            packet_id: packet_id.into(),
            source_revision_digest: source_revision_digest.into(),
            toolchain_digest: toolchain_digest.into(),
            configuration_digest: configuration_digest.into(),
            test_manifest_digest: test_manifest_digest.into(),
            request_digest: request_digest.into(),
            expected_terminal,
            expected_output_digest,
            expected_rollback_digest: expected_rollback_digest.into(),
            expected_untouched_digest: expected_untouched_digest.into(),
            expected_receipt_binding_digest: expected_receipt_binding_digest.into(),
            expected_recovery_frozen,
            host_prerequisites,
            retention_until,
            claim_ceiling: CLAIM_CEILING.into(),
            raw_payload_included: false,
            packet_digest: String::new(),
        };
        packet.validate_body()?;
        packet.packet_digest = packet.expected_digest()?;
        packet.validate()?;
        Ok(packet)
    }

    fn validate_body(&self) -> Result<()> {
        if self.schema_version != PACKET_SCHEMA
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.packet_id)
            || !valid_digest(&self.source_revision_digest)
            || !valid_digest(&self.toolchain_digest)
            || !valid_digest(&self.configuration_digest)
            || !valid_digest(&self.test_manifest_digest)
            || !valid_digest(&self.request_digest)
            || self
                .expected_output_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || !valid_digest(&self.expected_rollback_digest)
            || !valid_digest(&self.expected_untouched_digest)
            || !valid_digest(&self.expected_receipt_binding_digest)
            || self.host_prerequisites.is_empty()
            || self
                .host_prerequisites
                .iter()
                .any(|value| !valid_text(value))
            || self.retention_until == 0
            || self.claim_ceiling != CLAIM_CEILING
            || self.raw_payload_included
        {
            return Err(Error::Invalid("replication packet is malformed".into()));
        }
        if self.expected_terminal == ReplicationTerminal::Completed
            && self.expected_output_digest.is_none()
        {
            return Err(Error::Invalid(
                "completed replication packet lacks output digest".into(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String> {
        digest(&PacketIdentity {
            schema_version: &self.schema_version,
            state_slice: &self.state_slice,
            packet_id: &self.packet_id,
            source_revision_digest: &self.source_revision_digest,
            toolchain_digest: &self.toolchain_digest,
            configuration_digest: &self.configuration_digest,
            test_manifest_digest: &self.test_manifest_digest,
            request_digest: &self.request_digest,
            expected_terminal: self.expected_terminal,
            expected_output_digest: &self.expected_output_digest,
            expected_rollback_digest: &self.expected_rollback_digest,
            expected_untouched_digest: &self.expected_untouched_digest,
            expected_receipt_binding_digest: &self.expected_receipt_binding_digest,
            expected_recovery_frozen: self.expected_recovery_frozen,
            host_prerequisites: &self.host_prerequisites,
            retention_until: self.retention_until,
            claim_ceiling: &self.claim_ceiling,
            raw_payload_included: self.raw_payload_included,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_body()?;
        if !valid_digest(&self.packet_digest) || self.packet_digest != self.expected_digest()? {
            return Err(Error::Invalid("replication packet digest mismatch".into()));
        }
        Ok(())
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
        let packet: Self = serde_json::from_slice(&bytes)?;
        if canonical_bytes(&packet)? != bytes {
            return Err(Error::Journal(
                "replication packet is not canonical JSON".into(),
            ));
        }
        packet.validate()?;
        Ok(packet)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(packet) => Ok(packet),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let packet = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(packet)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Serialize)]
struct PacketIdentity<'a> {
    schema_version: &'a str,
    state_slice: &'a str,
    packet_id: &'a str,
    source_revision_digest: &'a str,
    toolchain_digest: &'a str,
    configuration_digest: &'a str,
    test_manifest_digest: &'a str,
    request_digest: &'a str,
    expected_terminal: ReplicationTerminal,
    expected_output_digest: &'a Option<String>,
    expected_rollback_digest: &'a str,
    expected_untouched_digest: &'a str,
    expected_receipt_binding_digest: &'a str,
    expected_recovery_frozen: bool,
    host_prerequisites: &'a BTreeSet<String>,
    retention_until: u64,
    claim_ceiling: &'a str,
    raw_payload_included: bool,
}

/// Digest-only aggregate produced by the replication operator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicationResult {
    pub schema_version: String,
    pub state_slice: String,
    pub packet_digest: String,
    pub operator_id: String,
    pub host_id: String,
    pub terminal: ReplicationTerminal,
    pub output_digest: Option<String>,
    pub rollback_digest: String,
    pub untouched_digest: String,
    pub receipt_binding_digest: String,
    pub recovery_frozen: bool,
    pub measured_at: u64,
}

impl ReplicationResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet: &FrozenReplicationPacket,
        operator_id: impl Into<String>,
        host_id: impl Into<String>,
        terminal: ReplicationTerminal,
        output_digest: Option<String>,
        rollback_digest: impl Into<String>,
        untouched_digest: impl Into<String>,
        receipt_binding_digest: impl Into<String>,
        recovery_frozen: bool,
        measured_at: u64,
    ) -> Result<Self> {
        packet.validate()?;
        let result = Self {
            schema_version: RESULT_SCHEMA.into(),
            state_slice: STATE_SLICE.into(),
            packet_digest: packet.packet_digest.clone(),
            operator_id: operator_id.into(),
            host_id: host_id.into(),
            terminal,
            output_digest,
            rollback_digest: rollback_digest.into(),
            untouched_digest: untouched_digest.into(),
            receipt_binding_digest: receipt_binding_digest.into(),
            recovery_frozen,
            measured_at,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RESULT_SCHEMA
            || self.state_slice != STATE_SLICE
            || !valid_digest(&self.packet_digest)
            || !valid_text(&self.operator_id)
            || !valid_text(&self.host_id)
            || self
                .output_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || !valid_digest(&self.rollback_digest)
            || !valid_digest(&self.untouched_digest)
            || !valid_digest(&self.receipt_binding_digest)
            || self.measured_at == 0
        {
            return Err(Error::Invalid("replication result is malformed".into()));
        }
        Ok(())
    }
}

/// Result plus a signature made by the replication operator's key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReplicationResult {
    pub result: ReplicationResult,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
}

/// Narrow signer for aggregate replication results. The private key never
/// appears in serialized or debug output.
pub struct ReplicationSigner {
    key_id: String,
    signing_key: SigningKey,
}

impl ReplicationSigner {
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; KEY_LEN]) -> Result<Self> {
        let key_id = key_id.into();
        if !valid_text(&key_id) {
            return Err(Error::Invalid(
                "replication signer key ID is malformed".into(),
            ));
        }
        Ok(Self {
            key_id,
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key_bytes(&self) -> [u8; KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, result: ReplicationResult) -> Result<SignedReplicationResult> {
        result.validate()?;
        let signature = self
            .signing_key
            .sign(&canonical_bytes(&result)?)
            .to_bytes()
            .to_vec();
        Ok(SignedReplicationResult {
            result,
            signer_key_id: self.key_id.clone(),
            signature,
        })
    }
}

pub fn verify_signed_result(
    signed: &SignedReplicationResult,
    expected_signer_key_id: &str,
    public_key: [u8; KEY_LEN],
) -> Result<()> {
    signed.result.validate()?;
    if !valid_text(expected_signer_key_id)
        || signed.signer_key_id != expected_signer_key_id
        || signed.signature.len() != SIGNATURE_LEN
    {
        return Err(Error::Rejected(
            "replication signer identity or signature is invalid".into(),
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| Error::Rejected("replication public key is invalid".into()))?;
    let signature_bytes: [u8; SIGNATURE_LEN] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Rejected("replication signature length is invalid".into()))?;
    verifying_key
        .verify(
            &canonical_bytes(&signed.result)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| Error::Rejected("replication signature verification failed".into()))
}

/// Compare a signed second-operator result against the frozen packet.
pub fn compare(
    packet: &FrozenReplicationPacket,
    signed: &SignedReplicationResult,
    expected_signer_key_id: &str,
    public_key: [u8; KEY_LEN],
) -> Result<ReplicationDisposition> {
    packet.validate()?;
    verify_signed_result(signed, expected_signer_key_id, public_key)?;
    let result = &signed.result;
    let matches = result.packet_digest == packet.packet_digest
        && result.terminal == packet.expected_terminal
        && result.output_digest == packet.expected_output_digest
        && result.rollback_digest == packet.expected_rollback_digest
        && result.untouched_digest == packet.expected_untouched_digest
        && result.receipt_binding_digest == packet.expected_receipt_binding_digest
        && result.recovery_frozen == packet.expected_recovery_frozen;
    if !matches {
        return Err(Error::Quarantined(
            "replication result does not match frozen packet".into(),
        ));
    }
    Ok(ReplicationDisposition::Matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: char) -> String {
        format!("{:064x}", value as u32)
    }

    fn packet() -> FrozenReplicationPacket {
        FrozenReplicationPacket::new(
            "packet-1",
            digest('a'),
            digest('b'),
            digest('c'),
            digest('d'),
            digest('e'),
            ReplicationTerminal::Completed,
            Some(digest('f')),
            digest('g'),
            digest('h'),
            digest('i'),
            false,
            ["macos-aarch64".into()].into_iter().collect(),
            100,
        )
        .expect("packet")
    }

    fn result(packet: &FrozenReplicationPacket) -> ReplicationResult {
        ReplicationResult::new(
            packet,
            "operator-b",
            "host-b",
            ReplicationTerminal::Completed,
            Some(digest('f')),
            digest('g'),
            digest('h'),
            digest('i'),
            false,
            10,
        )
        .expect("result")
    }

    #[test]
    fn signed_result_matches_frozen_packet() {
        let packet = packet();
        let signer = ReplicationSigner::from_seed("replication-key-b", [7; 32]).expect("signer");
        let signed = signer.sign(result(&packet)).expect("signed result");
        assert_eq!(
            compare(
                &packet,
                &signed,
                signer.key_id(),
                signer.verifying_key_bytes()
            )
            .expect("comparison"),
            ReplicationDisposition::Matched
        );
    }

    #[test]
    fn mismatch_is_quarantined_and_signature_tampering_rejected() {
        let packet = packet();
        let signer = ReplicationSigner::from_seed("replication-key-b", [8; 32]).expect("signer");
        let mut changed = result(&packet);
        changed.untouched_digest = digest('z');
        let signed_changed = signer.sign(changed).expect("signed changed result");
        assert!(matches!(
            compare(
                &packet,
                &signed_changed,
                signer.key_id(),
                signer.verifying_key_bytes()
            ),
            Err(Error::Quarantined(_))
        ));

        let mut forged = signer.sign(result(&packet)).expect("signed result");
        forged.signature[0] ^= 1;
        assert!(
            verify_signed_result(&forged, signer.key_id(), signer.verifying_key_bytes()).is_err()
        );
    }

    #[test]
    fn packet_persistence_is_canonical_and_recoverable() {
        let packet = packet();
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("replication.json");
        packet.save(&path).expect("save");
        assert_eq!(FrozenReplicationPacket::load(&path).expect("load"), packet);
        let bytes = std::fs::read(&path).expect("bytes");
        std::fs::write(path.with_extension("tmp"), bytes).expect("temporary");
        std::fs::remove_file(&path).expect("remove primary");
        assert_eq!(
            FrozenReplicationPacket::recover(&path).expect("recover"),
            packet
        );
    }
}
