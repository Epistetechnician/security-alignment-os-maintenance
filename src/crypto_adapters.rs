//! Offline crypto-adapter contracts for the foundation slice.
//!
//! State slice: `security-alignment-os-foundation-v1`.
//!
//! This module models the seam that a later, separately authorized chain or
//! payment adapter would consume. It prepares canonical zero-value dry-run
//! records, replays them through an append-only local journal, and compares a
//! caller-supplied observation with the frozen intent. It does not create a
//! wallet, hold a key, sign bytes, open a network connection, submit a
//! transaction, move value, or authorize a payout.

use crate::{canonical_bytes, digest, valid_digest, Error, Result, CLAIM_CEILING, STATE_SLICE};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const FORMAT_VERSION: u8 = 1;
const DRY_RUN_ACTION: &str = "prepare-only-v1";
const PROVIDER_KEY_FORMAT_VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;

fn valid_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<()> {
    let mut scanner = JsonKeyScanner { bytes, position: 0 };
    scanner.parse_value()?;
    scanner.skip_whitespace();
    if scanner.position != bytes.len() {
        return Err(Error::Journal(
            "crypto wire bytes contain trailing JSON data".into(),
        ));
    }
    Ok(())
}

struct JsonKeyScanner<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> JsonKeyScanner<'a> {
    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn parse_value(&mut self) -> Result<()> {
        self.skip_whitespace();
        match self.bytes.get(self.position).copied() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(Error::Journal("crypto wire JSON value is malformed".into())),
        }
    }

    fn parse_object(&mut self) -> Result<()> {
        self.position += 1;
        self.skip_whitespace();
        let mut keys = BTreeSet::new();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if !keys.insert(key) {
                return Err(Error::Journal(
                    "crypto wire JSON object contains duplicate keys".into(),
                ));
            }
            self.skip_whitespace();
            if self.bytes.get(self.position) != Some(&b':') {
                return Err(Error::Journal(
                    "crypto wire JSON object is missing a colon".into(),
                ));
            }
            self.position += 1;
            self.parse_value()?;
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(());
                }
                _ => {
                    return Err(Error::Journal(
                        "crypto wire JSON object separator is malformed".into(),
                    ))
                }
            }
        }
    }

    fn parse_array(&mut self) -> Result<()> {
        self.position += 1;
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(());
        }
        loop {
            self.parse_value()?;
            self.skip_whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(());
                }
                _ => {
                    return Err(Error::Journal(
                        "crypto wire JSON array separator is malformed".into(),
                    ))
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String> {
        let start = self.position;
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(Error::Journal(
                "crypto wire JSON object key is not a string".into(),
            ));
        }
        self.position += 1;
        loop {
            match self.bytes.get(self.position).copied() {
                Some(b'"') => {
                    self.position += 1;
                    return serde_json::from_slice(&self.bytes[start..self.position]).map_err(
                        |_| Error::Journal("crypto wire JSON string is malformed".into()),
                    );
                }
                Some(b'\\') => {
                    self.position += 1;
                    match self.bytes.get(self.position).copied() {
                        Some(b'u') => self.position += 5,
                        Some(_) => self.position += 1,
                        None => {
                            return Err(Error::Journal(
                                "crypto wire JSON escape is incomplete".into(),
                            ))
                        }
                    }
                }
                Some(byte) if byte < 0x20 => {
                    return Err(Error::Journal(
                        "crypto wire JSON string contains a control byte".into(),
                    ))
                }
                Some(_) => self.position += 1,
                None => {
                    return Err(Error::Journal(
                        "crypto wire JSON string is unterminated".into(),
                    ))
                }
            }
        }
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<()> {
        if self.bytes.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            Err(Error::Journal(
                "crypto wire JSON literal is malformed".into(),
            ))
        }
    }

    fn parse_number(&mut self) -> Result<()> {
        let start = self.position;
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}'))
        {
            self.position += 1;
        }
        if start == self.position {
            return Err(Error::Journal("crypto wire JSON number is empty".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AdapterKind {
    HyperliquidDryRun,
    EvmEscrowDryRun,
    TempoDryRun,
}

impl AdapterKind {
    pub const fn all() -> [Self; 3] {
        [
            Self::HyperliquidDryRun,
            Self::EvmEscrowDryRun,
            Self::TempoDryRun,
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChainIdentity {
    pub schema_version: u8,
    pub state_slice: String,
    pub adapter: AdapterKind,
    pub adapter_revision: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub asset: String,
}

impl ChainIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.adapter_revision)
            || self.chain_id == 0
            || !valid_text(&self.contract_address)
            || !valid_text(&self.asset)
        {
            return Err(Error::Invalid(
                "crypto adapter chain identity is incomplete".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRequest {
    pub intent_id: String,
    pub payment_id: String,
    pub beneficiary: String,
    pub specification_digest: String,
    pub policy_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl SettlementRequest {
    fn validate(&self) -> Result<()> {
        if !valid_text(&self.intent_id)
            || !valid_text(&self.payment_id)
            || !valid_text(&self.beneficiary)
            || !valid_digest(&self.specification_digest)
            || !valid_digest(&self.policy_digest)
            || self.expires_at <= self.created_at
        {
            return Err(Error::Invalid(
                "crypto settlement request is incomplete".into(),
            ));
        }
        Ok(())
    }
}

/// Registry-backed inputs used to derive accepted settlement eligibility.
pub struct SettlementEvidenceContext<'a> {
    pub proposal: &'a crate::market::SettlementProposal,
    pub job: &'a crate::market::SumJob,
    pub receipt: &'a crate::market::SumReceipt,
    pub evidence: &'a crate::EvidenceRegistry,
    pub evidence_id: &'a str,
    pub artifacts: &'a crate::artifacts::ArtifactRegistry,
    pub artifact_id: &'a str,
    pub checked_at: u64,
}

/// Complete local context for converting a market proposal into a dry-run intent.
pub struct SettlementIntentContext<'a> {
    pub proposal: &'a crate::market::SettlementProposal,
    pub job: &'a crate::market::SumJob,
    pub receipt: &'a crate::market::SumReceipt,
    pub chain: ChainIdentity,
    pub evidence: &'a crate::EvidenceRegistry,
    pub evidence_id: &'a str,
    pub artifacts: &'a crate::artifacts::ArtifactRegistry,
    pub artifact_id: &'a str,
    pub request: SettlementRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptedSettlementEvidence {
    pub schema_version: u8,
    pub state_slice: String,
    pub evidence_id: String,
    pub artifact_id: String,
    pub receipt_digest: String,
    pub evidence_record_digest: String,
    pub artifact_manifest_digest: String,
    pub checked_at: u64,
    pub eligibility_digest: String,
}

impl AcceptedSettlementEvidence {
    pub fn from_registries(context: SettlementEvidenceContext<'_>) -> Result<Self> {
        context.proposal.validate(context.job, context.receipt)?;
        context.receipt.validate(context.job, context.checked_at)?;
        let receipt_digest = digest(context.receipt)?;
        if !context
            .evidence
            .is_valid(context.evidence_id, context.checked_at, &receipt_digest)
        {
            return Err(Error::Rejected(
                "accepted settlement evidence is absent, stale, revoked, or receipt-mismatched"
                    .into(),
            ));
        }
        let evidence_record_digest = context.evidence.record_digest(context.evidence_id)?;
        let artifact = context.artifacts.require_valid(
            context.artifact_id,
            &evidence_record_digest,
            context.checked_at,
        )?;
        let binding = Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            evidence_id: context.evidence_id.into(),
            artifact_id: context.artifact_id.into(),
            receipt_digest,
            evidence_record_digest,
            artifact_manifest_digest: artifact.manifest.digest()?,
            checked_at: context.checked_at,
            eligibility_digest: String::new(),
        };
        let mut binding = binding;
        binding.eligibility_digest = binding.computed_digest()?;
        binding.validate(
            context.proposal,
            context.job,
            context.receipt,
            context.evidence,
            context.artifacts,
        )?;
        Ok(binding)
    }

    fn computed_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.eligibility_digest.clear();
        digest(&unsigned)
    }

    pub fn validate(
        &self,
        proposal: &crate::market::SettlementProposal,
        job: &crate::market::SumJob,
        receipt: &crate::market::SumReceipt,
        evidence: &crate::EvidenceRegistry,
        artifacts: &crate::artifacts::ArtifactRegistry,
    ) -> Result<()> {
        proposal.validate(job, receipt)?;
        receipt.validate(job, self.checked_at)?;
        if !valid_text(&self.evidence_id)
            || !valid_text(&self.artifact_id)
            || self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || self.receipt_digest != digest(receipt)?
            || !valid_digest(&self.evidence_record_digest)
            || !valid_digest(&self.artifact_manifest_digest)
            || self.checked_at < receipt.completed_at
            || !valid_digest(&self.eligibility_digest)
            || self.eligibility_digest != self.computed_digest()?
            || !evidence.is_valid(&self.evidence_id, self.checked_at, &self.receipt_digest)
        {
            return Err(Error::Rejected(
                "accepted settlement evidence binding is invalid".into(),
            ));
        }
        let evidence_record_digest = evidence.record_digest(&self.evidence_id)?;
        let artifact =
            artifacts.require_valid(&self.artifact_id, &evidence_record_digest, self.checked_at)?;
        if evidence_record_digest != self.evidence_record_digest
            || artifact.manifest.digest()? != self.artifact_manifest_digest
        {
            return Err(Error::Rejected(
                "accepted settlement artifact binding is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate_shape()?;
        digest(self)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.evidence_id)
            || !valid_text(&self.artifact_id)
            || !valid_digest(&self.receipt_digest)
            || !valid_digest(&self.evidence_record_digest)
            || !valid_digest(&self.artifact_manifest_digest)
            || !valid_digest(&self.eligibility_digest)
        {
            return Err(Error::Invalid(
                "accepted settlement evidence shape is malformed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IntentStatus {
    Proposed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementIntent {
    pub schema_version: u8,
    pub state_slice: String,
    pub intent_id: String,
    pub adapter: AdapterKind,
    pub adapter_revision: String,
    pub job_digest: String,
    pub specification_digest: String,
    pub artifact_digest: String,
    pub evidence_digest: String,
    pub eligibility_digest: String,
    pub receipt_digest: String,
    pub policy_digest: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub payment_id: String,
    pub beneficiary: String,
    pub amount: u64,
    pub asset: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: IntentStatus,
}

impl SettlementIntent {
    /// Converts an authorization-required local market proposal into a
    /// zero-value, caller-owned adapter intent.
    pub fn from_market_proposal(context: SettlementIntentContext<'_>) -> Result<Self> {
        context.proposal.validate(context.job, context.receipt)?;
        context.chain.validate()?;
        context.request.validate()?;
        let accepted = AcceptedSettlementEvidence::from_registries(SettlementEvidenceContext {
            proposal: context.proposal,
            job: context.job,
            receipt: context.receipt,
            evidence: context.evidence,
            evidence_id: context.evidence_id,
            artifacts: context.artifacts,
            artifact_id: context.artifact_id,
            checked_at: context.request.created_at,
        })?;
        if context.request.beneficiary != context.proposal.provider
            || context.request.created_at < context.receipt.completed_at
            || context.request.expires_at > context.job.deadline
        {
            return Err(Error::Rejected(
                "crypto intent does not bind the market proposal".into(),
            ));
        }
        let intent = Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            intent_id: context.request.intent_id,
            adapter: context.chain.adapter,
            adapter_revision: context.chain.adapter_revision,
            job_digest: context.job.digest()?,
            specification_digest: context.request.specification_digest,
            artifact_digest: accepted.artifact_manifest_digest,
            evidence_digest: accepted.evidence_record_digest,
            eligibility_digest: accepted.eligibility_digest,
            receipt_digest: context.proposal.receipt_digest.clone(),
            policy_digest: context.request.policy_digest,
            chain_id: context.chain.chain_id,
            contract_address: context.chain.contract_address,
            payment_id: context.request.payment_id,
            beneficiary: context.request.beneficiary,
            amount: 0,
            asset: context.chain.asset,
            created_at: context.request.created_at,
            expires_at: context.request.expires_at,
            status: IntentStatus::Proposed,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.intent_id)
            || !valid_text(&self.adapter_revision)
            || !valid_digest(&self.job_digest)
            || !valid_digest(&self.specification_digest)
            || !valid_digest(&self.artifact_digest)
            || !valid_digest(&self.evidence_digest)
            || !valid_digest(&self.eligibility_digest)
            || !valid_digest(&self.receipt_digest)
            || !valid_digest(&self.policy_digest)
            || self.chain_id == 0
            || !valid_text(&self.contract_address)
            || !valid_text(&self.payment_id)
            || !valid_text(&self.beneficiary)
            || self.amount != 0
            || !valid_text(&self.asset)
            || self.expires_at <= self.created_at
            || self.status != IntentStatus::Proposed
        {
            return Err(Error::Invalid(
                "crypto settlement intent violates the zero-value boundary".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }

    pub fn chain_identity(&self) -> ChainIdentity {
        ChainIdentity {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            adapter: self.adapter,
            adapter_revision: self.adapter_revision.clone(),
            chain_id: self.chain_id,
            contract_address: self.contract_address.clone(),
            asset: self.asset.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunAdapter {
    identity: ChainIdentity,
}

impl DryRunAdapter {
    pub fn new(identity: ChainIdentity) -> Result<Self> {
        identity.validate()?;
        Ok(Self { identity })
    }

    pub fn identity(&self) -> &ChainIdentity {
        &self.identity
    }

    pub fn prepare(&self, intent: &SettlementIntent, prepared_at: u64) -> Result<DryRunReceipt> {
        intent.validate()?;
        if self.identity != intent.chain_identity() {
            return Err(Error::Rejected(
                "crypto adapter identity does not bind the settlement intent".into(),
            ));
        }
        if prepared_at < intent.created_at || prepared_at >= intent.expires_at {
            return Err(Error::Rejected(
                "crypto adapter preparation is outside the intent window".into(),
            ));
        }
        let intent_digest = intent.digest()?;
        let request_digest = digest(&(
            DRY_RUN_ACTION,
            &intent_digest,
            self.identity.adapter,
            self.identity.chain_id,
            &self.identity.contract_address,
        ))?;
        let mut receipt = DryRunReceipt {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            adapter: self.identity.adapter,
            adapter_revision: self.identity.adapter_revision.clone(),
            intent_digest,
            payment_id: intent.payment_id.clone(),
            chain_id: self.identity.chain_id,
            contract_address: self.identity.contract_address.clone(),
            action: DRY_RUN_ACTION.into(),
            request_digest,
            prepared_at,
            signed: false,
            network_attempted: false,
            value_moved: false,
            claim_ceiling: CLAIM_CEILING.into(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.computed_digest()?;
        receipt.validate(intent)?;
        Ok(receipt)
    }

    pub fn prepare_wire(&self, intent: &SettlementIntent) -> Result<WireEnvelope> {
        intent.validate()?;
        if self.identity != intent.chain_identity() {
            return Err(Error::Rejected(
                "crypto adapter identity does not bind the settlement intent".into(),
            ));
        }
        let intent_digest = intent.digest()?;
        let identity = WireIdentity::from_intent(intent, &intent_digest);
        let mut envelope = match self.identity.adapter {
            AdapterKind::HyperliquidDryRun => WireEnvelope::Hyperliquid(HyperliquidWireEnvelope {
                identity,
                order_type: "dry-run-settlement-v1".into(),
                client_order_id: digest(&("hyperliquid-client-order-v1", &intent_digest))?,
                envelope_digest: String::new(),
            }),
            AdapterKind::EvmEscrowDryRun => WireEnvelope::EvmEscrow(EvmEscrowWireEnvelope {
                identity,
                method: "prepareEscrowSettlement".into(),
                calldata_digest: digest(&("evm-escrow-calldata-v1", &intent_digest))?,
                envelope_digest: String::new(),
            }),
            AdapterKind::TempoDryRun => WireEnvelope::Tempo(TempoWireEnvelope {
                identity,
                payment_memo_digest: digest(&("tempo-payment-memo-v1", &intent_digest))?,
                envelope_digest: String::new(),
            }),
        };
        envelope.set_digest()?;
        envelope.validate(intent)?;
        Ok(envelope)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DryRunReceipt {
    pub schema_version: u8,
    pub state_slice: String,
    pub adapter: AdapterKind,
    pub adapter_revision: String,
    pub intent_digest: String,
    pub payment_id: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub action: String,
    pub request_digest: String,
    pub prepared_at: u64,
    pub signed: bool,
    pub network_attempted: bool,
    pub value_moved: bool,
    pub claim_ceiling: String,
    pub receipt_digest: String,
}

impl DryRunReceipt {
    fn computed_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.receipt_digest.clear();
        digest(&unsigned)
    }

    pub fn validate(&self, intent: &SettlementIntent) -> Result<()> {
        intent.validate()?;
        let expected_request_digest = digest(&(
            DRY_RUN_ACTION,
            &intent.digest()?,
            intent.adapter,
            intent.chain_id,
            &intent.contract_address,
        ))?;
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || self.adapter != intent.adapter
            || self.adapter_revision != intent.adapter_revision
            || self.intent_digest != intent.digest()?
            || self.payment_id != intent.payment_id
            || self.chain_id != intent.chain_id
            || self.contract_address != intent.contract_address
            || self.action != DRY_RUN_ACTION
            || self.request_digest != expected_request_digest
            || self.prepared_at < intent.created_at
            || self.prepared_at >= intent.expires_at
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
            || !valid_digest(&self.intent_digest)
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.receipt_digest)
            || self.receipt_digest != self.computed_digest()?
        {
            return Err(Error::Rejected(
                "crypto dry-run receipt violates the foundation boundary".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        if self.receipt_digest.is_empty() {
            return Err(Error::Invalid(
                "crypto dry-run receipt has no digest".into(),
            ));
        }
        Ok(self.receipt_digest.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WireIdentity {
    pub schema_version: u8,
    pub state_slice: String,
    pub adapter_revision: String,
    pub intent_digest: String,
    pub payment_id: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub asset: String,
    pub beneficiary: String,
    pub amount: u64,
    pub action: String,
    pub signed: bool,
    pub network_attempted: bool,
    pub value_moved: bool,
    pub claim_ceiling: String,
}

impl WireIdentity {
    fn from_intent(intent: &SettlementIntent, intent_digest: &str) -> Self {
        Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            adapter_revision: intent.adapter_revision.clone(),
            intent_digest: intent_digest.into(),
            payment_id: intent.payment_id.clone(),
            chain_id: intent.chain_id,
            contract_address: intent.contract_address.clone(),
            asset: intent.asset.clone(),
            beneficiary: intent.beneficiary.clone(),
            amount: intent.amount,
            action: DRY_RUN_ACTION.into(),
            signed: false,
            network_attempted: false,
            value_moved: false,
            claim_ceiling: CLAIM_CEILING.into(),
        }
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.adapter_revision)
            || !valid_digest(&self.intent_digest)
            || !valid_text(&self.payment_id)
            || self.chain_id == 0
            || !valid_text(&self.contract_address)
            || !valid_text(&self.asset)
            || !valid_text(&self.beneficiary)
            || self.amount != 0
            || self.action != DRY_RUN_ACTION
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
        {
            return Err(Error::Rejected(
                "crypto wire identity violates the foundation boundary".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HyperliquidWireEnvelope {
    pub identity: WireIdentity,
    pub order_type: String,
    pub client_order_id: String,
    pub envelope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvmEscrowWireEnvelope {
    pub identity: WireIdentity,
    pub method: String,
    pub calldata_digest: String,
    pub envelope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TempoWireEnvelope {
    pub identity: WireIdentity,
    pub payment_memo_digest: String,
    pub envelope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WireEnvelope {
    Hyperliquid(HyperliquidWireEnvelope),
    EvmEscrow(EvmEscrowWireEnvelope),
    Tempo(TempoWireEnvelope),
}

impl WireEnvelope {
    pub fn adapter(&self) -> AdapterKind {
        match self {
            Self::Hyperliquid(_) => AdapterKind::HyperliquidDryRun,
            Self::EvmEscrow(_) => AdapterKind::EvmEscrowDryRun,
            Self::Tempo(_) => AdapterKind::TempoDryRun,
        }
    }

    fn identity(&self) -> &WireIdentity {
        match self {
            Self::Hyperliquid(envelope) => &envelope.identity,
            Self::EvmEscrow(envelope) => &envelope.identity,
            Self::Tempo(envelope) => &envelope.identity,
        }
    }

    fn set_digest(&mut self) -> Result<()> {
        let digest = self.computed_digest()?;
        match self {
            Self::Hyperliquid(envelope) => envelope.envelope_digest = digest,
            Self::EvmEscrow(envelope) => envelope.envelope_digest = digest,
            Self::Tempo(envelope) => envelope.envelope_digest = digest,
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String> {
        let unsigned = match self {
            Self::Hyperliquid(envelope) => {
                let mut unsigned = envelope.clone();
                unsigned.envelope_digest.clear();
                Self::Hyperliquid(unsigned)
            }
            Self::EvmEscrow(envelope) => {
                let mut unsigned = envelope.clone();
                unsigned.envelope_digest.clear();
                Self::EvmEscrow(unsigned)
            }
            Self::Tempo(envelope) => {
                let mut unsigned = envelope.clone();
                unsigned.envelope_digest.clear();
                Self::Tempo(unsigned)
            }
        };
        digest(&unsigned)
    }

    fn validate_shape(&self) -> Result<()> {
        self.identity().validate_shape()?;
        match self {
            Self::Hyperliquid(envelope) => {
                if envelope.order_type != "dry-run-settlement-v1"
                    || !valid_digest(&envelope.client_order_id)
                    || !valid_digest(&envelope.envelope_digest)
                    || envelope.envelope_digest != self.computed_digest()?
                {
                    return Err(Error::Rejected(
                        "Hyperliquid dry-run wire envelope is malformed".into(),
                    ));
                }
            }
            Self::EvmEscrow(envelope) => {
                if envelope.method != "prepareEscrowSettlement"
                    || !valid_digest(&envelope.calldata_digest)
                    || !valid_digest(&envelope.envelope_digest)
                    || envelope.envelope_digest != self.computed_digest()?
                {
                    return Err(Error::Rejected(
                        "EVM escrow dry-run wire envelope is malformed".into(),
                    ));
                }
            }
            Self::Tempo(envelope) => {
                if !valid_digest(&envelope.payment_memo_digest)
                    || !valid_digest(&envelope.envelope_digest)
                    || envelope.envelope_digest != self.computed_digest()?
                {
                    return Err(Error::Rejected(
                        "Tempo dry-run wire envelope is malformed".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self, intent: &SettlementIntent) -> Result<()> {
        intent.validate()?;
        self.validate_shape()?;
        if self.adapter() != intent.adapter
            || self.identity() != &WireIdentity::from_intent(intent, &intent.digest()?)
        {
            return Err(Error::Rejected(
                "crypto wire envelope does not bind the settlement intent".into(),
            ));
        }
        let intent_digest = intent.digest()?;
        match self {
            Self::Hyperliquid(envelope) => {
                if envelope.client_order_id
                    != digest(&("hyperliquid-client-order-v1", &intent_digest))?
                {
                    return Err(Error::Rejected(
                        "Hyperliquid dry-run client order binding mismatched".into(),
                    ));
                }
            }
            Self::EvmEscrow(envelope) => {
                if envelope.calldata_digest != digest(&("evm-escrow-calldata-v1", &intent_digest))?
                {
                    return Err(Error::Rejected(
                        "EVM escrow dry-run calldata binding mismatched".into(),
                    ));
                }
            }
            Self::Tempo(envelope) => {
                if envelope.payment_memo_digest
                    != digest(&("tempo-payment-memo-v1", &intent_digest))?
                {
                    return Err(Error::Rejected(
                        "Tempo dry-run payment memo binding mismatched".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical_bytes(self)
    }

    pub fn decode(adapter: AdapterKind, bytes: &[u8]) -> Result<Self> {
        reject_duplicate_json_keys(bytes)?;
        let envelope: Self = serde_json::from_slice(bytes)?;
        if envelope.adapter() != adapter {
            return Err(Error::Rejected(
                "crypto wire envelope adapter discriminator mismatched".into(),
            ));
        }
        if canonical_bytes(&envelope)? != bytes {
            return Err(Error::Journal(
                "crypto wire bytes are not canonical JSON".into(),
            ));
        }
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn digest(&self) -> Result<String> {
        self.validate_shape()?;
        match self {
            Self::Hyperliquid(envelope) => Ok(envelope.envelope_digest.clone()),
            Self::EvmEscrow(envelope) => Ok(envelope.envelope_digest.clone()),
            Self::Tempo(envelope) => Ok(envelope.envelope_digest.clone()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderKeyRecord {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ProviderKeyRegistry {
    records: BTreeMap<String, ProviderKeyRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProviderKeyDocument {
    version: u8,
    records: Vec<ProviderKeyRecord>,
}

impl ProviderKeyRegistry {
    pub fn validate(&self) -> Result<()> {
        for (key_id, record) in &self.records {
            if key_id != &record.key_id
                || !valid_text(key_id)
                || record.public_key.len() != 32
                || VerifyingKey::from_bytes(
                    &record.public_key.as_slice().try_into().map_err(|_| {
                        Error::Invalid("provider public key length is invalid".into())
                    })?,
                )
                .is_err()
            {
                return Err(Error::Invalid(
                    "provider key registry contains an invalid record".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn insert(&mut self, key_id: impl Into<String>, public_key: Vec<u8>) -> Result<()> {
        let key_id = key_id.into();
        if !valid_text(&key_id) || public_key.len() != 32 {
            return Err(Error::Invalid(
                "provider public key record is malformed".into(),
            ));
        }
        let key_bytes: [u8; 32] = public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("provider public key length is invalid".into()))?;
        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| Error::Invalid("provider public key is invalid".into()))?;
        if self.records.contains_key(&key_id) {
            return Err(Error::Rejected(
                "provider key identity already exists".into(),
            ));
        }
        self.records.insert(
            key_id.clone(),
            ProviderKeyRecord {
                key_id,
                public_key,
                revoked: false,
            },
        );
        self.validate()
    }

    pub fn revoke(&mut self, key_id: &str) -> Result<()> {
        let record = self
            .records
            .get_mut(key_id)
            .ok_or_else(|| Error::Invalid("provider key identity is unknown".into()))?;
        if record.revoked {
            return Err(Error::Rejected("provider key is already revoked".into()));
        }
        record.revoked = true;
        Ok(())
    }

    fn verify(&self, key_id: &str, message: &[u8], signature: &[u8]) -> Result<()> {
        self.validate()?;
        let record = self
            .records
            .get(key_id)
            .ok_or_else(|| Error::Rejected("provider signing key is not trusted".into()))?;
        if record.revoked {
            return Err(Error::Rejected("provider signing key is revoked".into()));
        }
        let key_bytes: [u8; 32] = record
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("provider public key length is invalid".into()))?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| Error::Invalid("provider public key is invalid".into()))?;
        let signature_bytes: [u8; SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| Error::Invalid("provider signature length is invalid".into()))?;
        key.verify(message, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| {
                Error::Rejected("provider observation signature verification failed".into())
            })
    }

    fn document(&self) -> ProviderKeyDocument {
        ProviderKeyDocument {
            version: PROVIDER_KEY_FORMAT_VERSION,
            records: self.records.values().cloned().collect(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(&self.document())?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let document: ProviderKeyDocument = serde_json::from_slice(&bytes)?;
        if document.version != PROVIDER_KEY_FORMAT_VERSION || canonical_bytes(&document)? != bytes {
            return Err(Error::Journal(
                "provider key registry bytes are not canonical JSON".into(),
            ));
        }
        let mut registry = Self::default();
        for record in document.records {
            let key_id = record.key_id;
            let public_key = record.public_key;
            let revoked = record.revoked;
            registry.insert(key_id.clone(), public_key)?;
            if revoked {
                registry.revoke(&key_id)?;
            }
        }
        registry.validate()?;
        Ok(registry)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(registry) => Ok(registry),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let registry = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(registry)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ObservationStatus {
    NotFound,
    Observed,
    Ambiguous,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconciliationObservation {
    pub schema_version: u8,
    pub state_slice: String,
    pub observation_id: String,
    pub adapter: AdapterKind,
    pub adapter_revision: String,
    pub intent_digest: String,
    pub payment_id: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub status: ObservationStatus,
    pub transaction_digest: Option<String>,
    pub observed_amount: u64,
    pub asset: String,
    pub beneficiary: String,
    pub observed_at: u64,
}

impl ReconciliationObservation {
    pub fn validate(&self) -> Result<()> {
        let transaction_shape_is_valid = match (&self.status, &self.transaction_digest) {
            (ObservationStatus::Observed, Some(transaction_digest)) => {
                valid_digest(transaction_digest)
            }
            (ObservationStatus::NotFound | ObservationStatus::Ambiguous, None) => true,
            _ => false,
        };
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.observation_id)
            || !valid_text(&self.adapter_revision)
            || !valid_digest(&self.intent_digest)
            || !valid_text(&self.payment_id)
            || self.chain_id == 0
            || !valid_text(&self.contract_address)
            || !transaction_shape_is_valid
            || self.observed_amount != 0
            || !valid_text(&self.asset)
            || !valid_text(&self.beneficiary)
        {
            return Err(Error::Invalid(
                "crypto reconciliation observation is malformed".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest(self)
    }
}

/// A provider-signed observation envelope for offline authenticity checking.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderObservationEnvelope {
    pub schema_version: u8,
    pub state_slice: String,
    pub provider_id: String,
    pub key_id: String,
    pub observation: ReconciliationObservation,
    pub observation_digest: String,
    pub signature: Vec<u8>,
}

impl ProviderObservationEnvelope {
    pub fn unsigned(
        provider_id: impl Into<String>,
        key_id: impl Into<String>,
        observation: ReconciliationObservation,
    ) -> Result<Self> {
        let envelope = Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            provider_id: provider_id.into(),
            key_id: key_id.into(),
            observation_digest: observation.digest()?,
            observation,
            signature: Vec::new(),
        };
        envelope.validate_unsigned_shape()?;
        Ok(envelope)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate_unsigned_shape()?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        canonical_bytes(&unsigned)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        reject_duplicate_json_keys(bytes)?;
        let envelope: Self = serde_json::from_slice(bytes)?;
        if canonical_bytes(&envelope)? != bytes {
            return Err(Error::Journal(
                "provider observation bytes are not canonical JSON".into(),
            ));
        }
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        keys: &ProviderKeyRegistry,
        intent: &SettlementIntent,
    ) -> Result<ReconciliationObservation> {
        intent.validate()?;
        self.validate()?;
        if self.provider_id != self.observation.beneficiary {
            return Err(Error::Quarantined(
                "provider observation identity does not bind the beneficiary".into(),
            ));
        }
        if !observation_identity_matches(intent, &self.observation)? {
            return Err(Error::Quarantined(
                "provider observation identity does not bind the settlement intent".into(),
            ));
        }
        keys.verify(&self.key_id, &self.signing_bytes()?, &self.signature)?;
        Ok(self.observation.clone())
    }

    pub fn verify_and_reconcile(
        &self,
        keys: &ProviderKeyRegistry,
        intent: &SettlementIntent,
    ) -> Result<ReconciliationResult> {
        let observation = self.verify(keys, intent)?;
        reconcile(intent, &observation)
    }

    fn validate(&self) -> Result<()> {
        self.validate_unsigned_shape()?;
        if self.signature.len() != SIGNATURE_LEN {
            return Err(Error::Invalid(
                "provider observation signature length is invalid".into(),
            ));
        }
        Ok(())
    }

    fn validate_unsigned_shape(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_text(&self.provider_id)
            || !valid_text(&self.key_id)
            || self.observation_digest != self.observation.digest()?
            || !valid_digest(&self.observation_digest)
        {
            return Err(Error::Invalid(
                "provider observation envelope is malformed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReconciliationStatus {
    Matched,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconciliationResult {
    pub schema_version: u8,
    pub state_slice: String,
    pub intent_digest: String,
    pub observation_digest: String,
    pub status: ReconciliationStatus,
    pub payout_authorized: bool,
    pub signed: bool,
    pub network_attempted: bool,
    pub value_moved: bool,
    pub claim_ceiling: String,
    pub result_digest: String,
}

impl ReconciliationResult {
    fn computed_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.result_digest.clear();
        digest(&unsigned)
    }

    pub fn validate(
        &self,
        intent: &SettlementIntent,
        observation: &ReconciliationObservation,
    ) -> Result<()> {
        intent.validate()?;
        observation.validate()?;
        let identity_matches = observation_identity_matches(intent, observation)?;
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || self.intent_digest != intent.digest()?
            || self.observation_digest != observation.digest()?
            || self.status != ReconciliationStatus::Matched
            || observation.status != ObservationStatus::Observed
            || !identity_matches
            || self.payout_authorized
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
            || !valid_digest(&self.result_digest)
            || self.result_digest != self.computed_digest()?
        {
            return Err(Error::Rejected(
                "crypto reconciliation result violates the foundation boundary".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        if self.result_digest.is_empty() {
            return Err(Error::Invalid(
                "crypto reconciliation result has no digest".into(),
            ));
        }
        Ok(self.result_digest.clone())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorizationStatus {
    AuthorizationRequired,
}

/// Proposal-only resolution produced after an exact local reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementResolution {
    pub schema_version: u8,
    pub state_slice: String,
    pub intent_digest: String,
    pub reconciliation_digest: String,
    pub evidence_digest: String,
    pub artifact_digest: String,
    pub eligibility_digest: String,
    pub policy_digest: String,
    pub payment_id: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub asset: String,
    pub beneficiary: String,
    pub amount: u64,
    pub status: AuthorizationStatus,
    pub payout_authorized: bool,
    pub signed: bool,
    pub network_attempted: bool,
    pub value_moved: bool,
    pub claim_ceiling: String,
    pub resolution_digest: String,
}

impl SettlementResolution {
    pub fn from_reconciliation(
        intent: &SettlementIntent,
        observation: &ReconciliationObservation,
        reconciliation: &ReconciliationResult,
    ) -> Result<Self> {
        intent.validate()?;
        reconciliation.validate(intent, observation)?;
        let mut resolution = Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            intent_digest: intent.digest()?,
            reconciliation_digest: reconciliation.digest()?,
            evidence_digest: intent.evidence_digest.clone(),
            artifact_digest: intent.artifact_digest.clone(),
            eligibility_digest: intent.eligibility_digest.clone(),
            policy_digest: intent.policy_digest.clone(),
            payment_id: intent.payment_id.clone(),
            chain_id: intent.chain_id,
            contract_address: intent.contract_address.clone(),
            asset: intent.asset.clone(),
            beneficiary: intent.beneficiary.clone(),
            amount: 0,
            status: AuthorizationStatus::AuthorizationRequired,
            payout_authorized: false,
            signed: false,
            network_attempted: false,
            value_moved: false,
            claim_ceiling: CLAIM_CEILING.into(),
            resolution_digest: String::new(),
        };
        resolution.resolution_digest = resolution.computed_digest()?;
        resolution.validate(intent, observation, reconciliation)?;
        Ok(resolution)
    }

    fn computed_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.resolution_digest.clear();
        digest(&unsigned)
    }

    pub fn validate(
        &self,
        intent: &SettlementIntent,
        observation: &ReconciliationObservation,
        reconciliation: &ReconciliationResult,
    ) -> Result<()> {
        intent.validate()?;
        reconciliation.validate(intent, observation)?;
        self.validate_shape()?;
        if self.intent_digest != intent.digest()?
            || self.reconciliation_digest != reconciliation.digest()?
            || self.evidence_digest != intent.evidence_digest
            || self.artifact_digest != intent.artifact_digest
            || self.eligibility_digest != intent.eligibility_digest
            || self.policy_digest != intent.policy_digest
            || self.payment_id != intent.payment_id
            || self.chain_id != intent.chain_id
            || self.contract_address != intent.contract_address
            || self.asset != intent.asset
            || self.beneficiary != intent.beneficiary
            || self.amount != 0
            || self.status != AuthorizationStatus::AuthorizationRequired
            || self.payout_authorized
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
            || self.resolution_digest != self.computed_digest()?
        {
            return Err(Error::Rejected(
                "crypto settlement resolution violates the authorization boundary".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate_shape()?;
        Ok(self.resolution_digest.clone())
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_digest(&self.intent_digest)
            || !valid_digest(&self.reconciliation_digest)
            || !valid_digest(&self.evidence_digest)
            || !valid_digest(&self.artifact_digest)
            || !valid_digest(&self.eligibility_digest)
            || !valid_digest(&self.policy_digest)
            || !valid_text(&self.payment_id)
            || self.chain_id == 0
            || !valid_text(&self.contract_address)
            || !valid_text(&self.asset)
            || !valid_text(&self.beneficiary)
            || self.amount != 0
            || self.status != AuthorizationStatus::AuthorizationRequired
            || self.payout_authorized
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
            || !valid_digest(&self.resolution_digest)
        {
            return Err(Error::Rejected(
                "crypto settlement resolution shape violates the authorization boundary".into(),
            ));
        }
        Ok(())
    }
}

/// A deterministic, zero-value payout proposal awaiting external authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayoutProposal {
    pub schema_version: u8,
    pub state_slice: String,
    pub intent_digest: String,
    pub resolution_digest: String,
    pub evidence_digest: String,
    pub artifact_digest: String,
    pub eligibility_digest: String,
    pub policy_digest: String,
    pub payment_id: String,
    pub idempotency_key: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub asset: String,
    pub beneficiary: String,
    pub amount: u64,
    pub status: AuthorizationStatus,
    pub payout_authorized: bool,
    pub signed: bool,
    pub network_attempted: bool,
    pub value_moved: bool,
    pub claim_ceiling: String,
    pub request_digest: String,
    pub proposal_digest: String,
}

impl PayoutProposal {
    pub fn from_resolution(
        intent: &SettlementIntent,
        resolution: &SettlementResolution,
    ) -> Result<Self> {
        intent.validate()?;
        resolution.validate_shape()?;
        let resolution_digest = resolution.digest()?;
        let mut proposal = Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            intent_digest: intent.digest()?,
            resolution_digest: resolution_digest.clone(),
            evidence_digest: intent.evidence_digest.clone(),
            artifact_digest: intent.artifact_digest.clone(),
            eligibility_digest: intent.eligibility_digest.clone(),
            policy_digest: intent.policy_digest.clone(),
            payment_id: intent.payment_id.clone(),
            idempotency_key: intent.payment_id.clone(),
            chain_id: intent.chain_id,
            contract_address: intent.contract_address.clone(),
            asset: intent.asset.clone(),
            beneficiary: intent.beneficiary.clone(),
            amount: 0,
            status: AuthorizationStatus::AuthorizationRequired,
            payout_authorized: false,
            signed: false,
            network_attempted: false,
            value_moved: false,
            claim_ceiling: CLAIM_CEILING.into(),
            request_digest: digest(&(
                "payout-proposal-request-v1",
                &intent.payment_id,
                &resolution_digest,
                &intent.policy_digest,
            ))?,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.computed_digest()?;
        proposal.validate(intent, resolution)?;
        Ok(proposal)
    }

    fn computed_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.proposal_digest.clear();
        digest(&unsigned)
    }

    pub fn validate(
        &self,
        intent: &SettlementIntent,
        resolution: &SettlementResolution,
    ) -> Result<()> {
        intent.validate()?;
        resolution.validate_shape()?;
        self.validate_shape()?;
        if self.intent_digest != intent.digest()?
            || self.resolution_digest != resolution.digest()?
            || self.evidence_digest != intent.evidence_digest
            || self.artifact_digest != intent.artifact_digest
            || self.eligibility_digest != intent.eligibility_digest
            || self.policy_digest != intent.policy_digest
            || self.payment_id != intent.payment_id
            || self.idempotency_key != intent.payment_id
            || self.chain_id != intent.chain_id
            || self.contract_address != intent.contract_address
            || self.asset != intent.asset
            || self.beneficiary != intent.beneficiary
            || self.amount != 0
            || self.status != AuthorizationStatus::AuthorizationRequired
            || self.payout_authorized
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
            || self.request_digest
                != digest(&(
                    "payout-proposal-request-v1",
                    &intent.payment_id,
                    &resolution.digest()?,
                    &intent.policy_digest,
                ))?
            || self.proposal_digest != self.computed_digest()?
        {
            return Err(Error::Rejected(
                "crypto payout proposal violates the authorization boundary".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate_shape()?;
        Ok(self.proposal_digest.clone())
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != FORMAT_VERSION
            || self.state_slice != STATE_SLICE
            || !valid_digest(&self.intent_digest)
            || !valid_digest(&self.resolution_digest)
            || !valid_digest(&self.evidence_digest)
            || !valid_digest(&self.artifact_digest)
            || !valid_digest(&self.eligibility_digest)
            || !valid_digest(&self.policy_digest)
            || !valid_text(&self.payment_id)
            || self.idempotency_key != self.payment_id
            || self.chain_id == 0
            || !valid_text(&self.contract_address)
            || !valid_text(&self.asset)
            || !valid_text(&self.beneficiary)
            || self.amount != 0
            || self.status != AuthorizationStatus::AuthorizationRequired
            || self.payout_authorized
            || self.signed
            || self.network_attempted
            || self.value_moved
            || self.claim_ceiling != CLAIM_CEILING
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.proposal_digest)
        {
            return Err(Error::Rejected(
                "crypto payout proposal shape violates the authorization boundary".into(),
            ));
        }
        Ok(())
    }
}

pub fn reconcile(
    intent: &SettlementIntent,
    observation: &ReconciliationObservation,
) -> Result<ReconciliationResult> {
    intent.validate()?;
    observation.validate()?;
    if !observation_identity_matches(intent, observation)? {
        return Err(Error::Quarantined(
            "crypto reconciliation identity or zero-value binding mismatched".into(),
        ));
    }
    match observation.status {
        ObservationStatus::NotFound => Err(Error::Rejected(
            "crypto payment was not observed; no payout is authorized".into(),
        )),
        ObservationStatus::Ambiguous => Err(Error::Quarantined(
            "crypto payment observation is ambiguous; payout is frozen".into(),
        )),
        ObservationStatus::Observed => {
            let mut result = ReconciliationResult {
                schema_version: FORMAT_VERSION,
                state_slice: STATE_SLICE.into(),
                intent_digest: intent.digest()?,
                observation_digest: observation.digest()?,
                status: ReconciliationStatus::Matched,
                payout_authorized: false,
                signed: false,
                network_attempted: false,
                value_moved: false,
                claim_ceiling: CLAIM_CEILING.into(),
                result_digest: String::new(),
            };
            result.result_digest = result.computed_digest()?;
            result.validate(intent, observation)?;
            Ok(result)
        }
    }
}

fn observation_identity_matches(
    intent: &SettlementIntent,
    observation: &ReconciliationObservation,
) -> Result<bool> {
    Ok(observation.adapter == intent.adapter
        && observation.adapter_revision == intent.adapter_revision
        && observation.intent_digest == intent.digest()?
        && observation.payment_id == intent.payment_id
        && observation.chain_id == intent.chain_id
        && observation.contract_address == intent.contract_address
        && observation.asset == intent.asset
        && observation.beneficiary == intent.beneficiary)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AdapterEventKind {
    Proposed,
    DryRunPrepared,
    Reconciled,
    PayoutProposed,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CryptoEvent {
    pub schema_version: u8,
    pub state_slice: String,
    pub sequence: u64,
    pub intent_digest: String,
    pub idempotency_key: String,
    pub kind: AdapterEventKind,
    pub subject_digest: String,
    pub previous_event_digest: Option<String>,
    pub recorded_at: u64,
    pub event_digest: String,
}

impl CryptoEvent {
    fn computed_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.event_digest.clear();
        digest(&unsigned)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CryptoJournal {
    events: Vec<CryptoEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct JournalDocument {
    version: u8,
    events: Vec<CryptoEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendDisposition {
    Appended,
    AlreadyPresent,
}

impl CryptoJournal {
    pub fn events(&self) -> &[CryptoEvent] {
        &self.events
    }

    pub fn validate(&self) -> Result<()> {
        let mut previous_event_digest = None;
        let mut states = BTreeMap::new();
        let mut idempotency_keys = BTreeMap::new();
        let mut intent_keys = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for (expected_sequence, event) in self.events.iter().enumerate() {
            if event.schema_version != FORMAT_VERSION
                || event.state_slice != STATE_SLICE
                || event.sequence != expected_sequence as u64
                || !valid_digest(&event.intent_digest)
                || !valid_text(&event.idempotency_key)
                || !valid_digest(&event.subject_digest)
                || event.previous_event_digest != previous_event_digest
                || !valid_digest(&event.event_digest)
                || event.event_digest != event.computed_digest()?
            {
                return Err(Error::Journal(
                    "crypto journal event is malformed or not hash chained".into(),
                ));
            }
            if let Some(existing_intent) =
                idempotency_keys.insert(event.idempotency_key.clone(), event.intent_digest.clone())
            {
                if existing_intent != event.intent_digest {
                    return Err(Error::Journal(
                        "crypto idempotency key was reused for another intent".into(),
                    ));
                }
            }
            if let Some(existing_key) =
                intent_keys.insert(event.intent_digest.clone(), event.idempotency_key.clone())
            {
                if existing_key != event.idempotency_key {
                    return Err(Error::Journal(
                        "crypto intent was assigned multiple idempotency keys".into(),
                    ));
                }
            }
            if !identities.insert((
                event.intent_digest.clone(),
                event.kind,
                event.subject_digest.clone(),
            )) {
                return Err(Error::Journal(
                    "crypto journal contains a duplicate event identity".into(),
                ));
            }
            let current = states.get(&event.intent_digest).copied();
            if !transition_is_valid(current, event.kind) {
                return Err(Error::Journal(
                    "crypto journal contains an invalid intent transition".into(),
                ));
            }
            states.insert(event.intent_digest.clone(), event.kind);
            previous_event_digest = Some(event.event_digest.clone());
        }
        Ok(())
    }

    pub fn state(&self, intent_digest: &str) -> Result<Option<AdapterEventKind>> {
        self.validate()?;
        if !valid_digest(intent_digest) {
            return Err(Error::Invalid("crypto intent digest is malformed".into()));
        }
        Ok(self
            .events
            .iter()
            .rev()
            .find(|event| event.intent_digest == intent_digest)
            .map(|event| event.kind))
    }

    pub fn append_proposed(
        &mut self,
        intent: &SettlementIntent,
        recorded_at: u64,
    ) -> Result<AppendDisposition> {
        intent.validate()?;
        let intent_digest = intent.digest()?;
        self.append_event(
            &intent_digest,
            &intent.payment_id,
            AdapterEventKind::Proposed,
            &intent_digest,
            recorded_at,
        )
    }

    pub fn append_prepared(
        &mut self,
        intent: &SettlementIntent,
        receipt: &DryRunReceipt,
        recorded_at: u64,
    ) -> Result<AppendDisposition> {
        receipt.validate(intent)?;
        let intent_digest = intent.digest()?;
        if receipt.intent_digest != intent_digest {
            return Err(Error::Quarantined(
                "crypto dry-run receipt is bound to another intent".into(),
            ));
        }
        let receipt_digest = receipt.digest()?;
        self.append_event(
            &intent_digest,
            &intent.payment_id,
            AdapterEventKind::DryRunPrepared,
            &receipt_digest,
            recorded_at,
        )
    }

    pub fn append_reconciled(
        &mut self,
        intent: &SettlementIntent,
        observation: &ReconciliationObservation,
        result: &ReconciliationResult,
        recorded_at: u64,
    ) -> Result<AppendDisposition> {
        result.validate(intent, observation)?;
        let intent_digest = intent.digest()?;
        self.append_event(
            &intent_digest,
            &intent.payment_id,
            AdapterEventKind::Reconciled,
            &result.digest()?,
            recorded_at,
        )
    }

    pub fn append_payout_proposed(
        &mut self,
        intent: &SettlementIntent,
        resolution: &SettlementResolution,
        payout: &PayoutProposal,
        recorded_at: u64,
    ) -> Result<AppendDisposition> {
        payout.validate(intent, resolution)?;
        let intent_digest = intent.digest()?;
        if payout.intent_digest != intent_digest {
            return Err(Error::Quarantined(
                "crypto payout proposal is bound to another intent".into(),
            ));
        }
        self.append_event(
            &intent_digest,
            &intent.payment_id,
            AdapterEventKind::PayoutProposed,
            &payout.digest()?,
            recorded_at,
        )
    }

    pub fn append_quarantined(
        &mut self,
        intent: &SettlementIntent,
        subject_digest: &str,
        recorded_at: u64,
    ) -> Result<AppendDisposition> {
        intent.validate()?;
        if !valid_digest(subject_digest) {
            return Err(Error::Invalid(
                "crypto quarantine subject digest is malformed".into(),
            ));
        }
        let intent_digest = intent.digest()?;
        self.append_event(
            &intent_digest,
            &intent.payment_id,
            AdapterEventKind::Quarantined,
            subject_digest,
            recorded_at,
        )
    }

    fn append_event(
        &mut self,
        intent_digest: &str,
        idempotency_key: &str,
        kind: AdapterEventKind,
        subject_digest: &str,
        recorded_at: u64,
    ) -> Result<AppendDisposition> {
        self.validate()?;
        if !valid_digest(intent_digest)
            || !valid_text(idempotency_key)
            || !valid_digest(subject_digest)
        {
            return Err(Error::Invalid("crypto journal append is malformed".into()));
        }
        if let Some(existing) = self
            .events
            .iter()
            .find(|event| event.intent_digest == intent_digest && event.kind == kind)
        {
            if existing.idempotency_key == idempotency_key
                && existing.subject_digest == subject_digest
            {
                return Ok(AppendDisposition::AlreadyPresent);
            }
            return Err(Error::Quarantined(
                "crypto idempotency key already has a different subject".into(),
            ));
        }
        if self.events.iter().any(|event| {
            event.idempotency_key == idempotency_key && event.intent_digest != intent_digest
        }) {
            return Err(Error::Quarantined(
                "crypto idempotency key belongs to another intent".into(),
            ));
        }
        if self.events.iter().any(|event| {
            event.intent_digest == intent_digest && event.idempotency_key != idempotency_key
        }) {
            return Err(Error::Quarantined(
                "crypto intent already has another idempotency key".into(),
            ));
        }
        let current = self
            .events
            .iter()
            .rev()
            .find(|event| event.intent_digest == intent_digest)
            .map(|event| event.kind);
        if !transition_is_valid(current, kind) {
            return Err(Error::Rejected(
                "crypto journal transition is not allowed".into(),
            ));
        }
        let mut event = CryptoEvent {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            sequence: self.events.len() as u64,
            intent_digest: intent_digest.into(),
            idempotency_key: idempotency_key.into(),
            kind,
            subject_digest: subject_digest.into(),
            previous_event_digest: self.events.last().map(|event| event.event_digest.clone()),
            recorded_at,
            event_digest: String::new(),
        };
        event.event_digest = event.computed_digest()?;
        self.events.push(event);
        self.validate()?;
        Ok(AppendDisposition::Appended)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let document = JournalDocument {
            version: FORMAT_VERSION,
            events: self.events.clone(),
        };
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, canonical_bytes(&document)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        let document: JournalDocument = serde_json::from_slice(&bytes)?;
        if document.version != FORMAT_VERSION || canonical_bytes(&document)? != bytes {
            return Err(Error::Journal(
                "crypto journal bytes are not canonical JSON".into(),
            ));
        }
        let journal = Self {
            events: document.events,
        };
        journal.validate()?;
        Ok(journal)
    }

    pub fn recover(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(journal) => Ok(journal),
            Err(Error::Persistence(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let temporary = path.with_extension("tmp");
                let journal = Self::load(&temporary)?;
                fs::rename(temporary, path)?;
                Ok(journal)
            }
            Err(error) => Err(error),
        }
    }
}

fn transition_is_valid(current: Option<AdapterEventKind>, next: AdapterEventKind) -> bool {
    matches!(
        (current, next),
        (None, AdapterEventKind::Proposed)
            | (
                Some(AdapterEventKind::Proposed),
                AdapterEventKind::DryRunPrepared
            )
            | (
                Some(AdapterEventKind::Proposed),
                AdapterEventKind::Quarantined
            )
            | (
                Some(AdapterEventKind::DryRunPrepared),
                AdapterEventKind::Reconciled
            )
            | (
                Some(AdapterEventKind::DryRunPrepared),
                AdapterEventKind::Quarantined
            )
            | (
                Some(AdapterEventKind::Reconciled),
                AdapterEventKind::PayoutProposed
            )
    )
}
