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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const FORMAT_VERSION: u8 = 1;
const DRY_RUN_ACTION: &str = "prepare-only-v1";

fn valid_text(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
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
    pub artifact_digest: String,
    pub accepted_evidence_digest: String,
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
            || !valid_digest(&self.artifact_digest)
            || !valid_digest(&self.accepted_evidence_digest)
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
    pub fn from_market_proposal(
        proposal: &crate::market::SettlementProposal,
        job: &crate::market::SumJob,
        receipt: &crate::market::SumReceipt,
        chain: ChainIdentity,
        request: SettlementRequest,
    ) -> Result<Self> {
        proposal.validate(job, receipt)?;
        chain.validate()?;
        request.validate()?;
        if request.beneficiary != proposal.provider
            || request.created_at < receipt.completed_at
            || request.expires_at > job.deadline
        {
            return Err(Error::Rejected(
                "crypto intent does not bind the market proposal".into(),
            ));
        }
        let intent = Self {
            schema_version: FORMAT_VERSION,
            state_slice: STATE_SLICE.into(),
            intent_id: request.intent_id,
            adapter: chain.adapter,
            adapter_revision: chain.adapter_revision,
            job_digest: job.digest()?,
            specification_digest: request.specification_digest,
            artifact_digest: request.artifact_digest,
            evidence_digest: request.accepted_evidence_digest,
            receipt_digest: proposal.receipt_digest.clone(),
            policy_digest: request.policy_digest,
            chain_id: chain.chain_id,
            contract_address: chain.contract_address,
            payment_id: request.payment_id,
            beneficiary: request.beneficiary,
            amount: 0,
            asset: chain.asset,
            created_at: request.created_at,
            expires_at: request.expires_at,
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
    )
}
