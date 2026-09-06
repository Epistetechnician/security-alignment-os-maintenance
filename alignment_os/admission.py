"""Deterministic proposal admission and capability issuance."""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import digest_object
from .journal import AdmissionJournal, JournalError
from .models import (
    ActionCandidate,
    AdmissionDecision,
    CapabilityToken,
    ClaimMaturity,
    DecisionKind,
)


@dataclass(frozen=True)
class AdmissionPolicy:
    allowed_actions: frozenset[str] = frozenset({"read", "write"})
    allowed_scopes: frozenset[str] = frozenset({"public", "sandbox"})
    required_claim: str = "PolicyCompliance"
    minimum_maturity: ClaimMaturity = ClaimMaturity.LOCAL
    max_cost: dict[str, int] = field(
        default_factory=lambda: {"cpu_ms": 1_000, "bytes": 1_000_000, "spend": 0}
    )
    token_ttl: int = 30


class AdmissionKernel:
    def __init__(self, policy: AdmissionPolicy | None = None, journal: AdmissionJournal | None = None) -> None:
        self.policy = policy or AdmissionPolicy()
        self.journal = journal or AdmissionJournal()

    def _decision(self, candidate: ActionCandidate, kind: DecisionKind, reason: str, capability: CapabilityToken | None = None) -> AdmissionDecision:
        candidate_digest = digest_object(candidate)
        decision_digest = digest_object({"candidate_digest": candidate_digest, "decision": kind, "reason": reason})
        decision = AdmissionDecision(
            candidate_id=candidate.candidate_id,
            decision=kind,
            reason=reason,
            candidate_digest=candidate_digest,
            decision_digest=decision_digest,
            capability=capability,
        )
        self.journal.append(candidate_digest, decision)
        return decision

    def admit(self, candidate: ActionCandidate, now: int) -> AdmissionDecision:
        candidate_digest = digest_object(candidate)
        if self.journal.contains_candidate(candidate_digest):
            return AdmissionDecision(
                candidate_id=candidate.candidate_id,
                decision=DecisionKind.REJECTED,
                reason="replayed candidate",
                candidate_digest=candidate_digest,
                decision_digest=digest_object({"candidate_digest": candidate_digest, "reason": "replayed candidate"}),
            )
        if not candidate.candidate_id or not candidate.agent_id or not candidate.intent:
            return self._decision(candidate, DecisionKind.REJECTED, "missing identity or intent")
        if candidate.requests_direct_authority:
            return self._decision(candidate, DecisionKind.REJECTED, "model requested direct authority")
        if not candidate.source_digest or len(candidate.source_digest) != 64:
            return self._decision(candidate, DecisionKind.QUARANTINED, "missing source digest")
        if candidate.expires_at <= now:
            return self._decision(candidate, DecisionKind.REJECTED, "expired candidate")
        if candidate.action.value not in self.policy.allowed_actions:
            return self._decision(candidate, DecisionKind.REJECTED, "action is not allowlisted")
        if candidate.scope not in self.policy.allowed_scopes:
            return self._decision(candidate, DecisionKind.REJECTED, "scope is not allowlisted")
        for axis, amount in candidate.resource_cost.items():
            if not isinstance(amount, int) or amount < 0:
                return self._decision(candidate, DecisionKind.REJECTED, "invalid resource cost")
            if amount > self.policy.max_cost.get(axis, 0):
                return self._decision(candidate, DecisionKind.REJECTED, f"resource budget exceeded: {axis}")
        if not any(self.policy.required_claim in claim.guarantees and claim.closed and claim.maturity.rank >= self.policy.minimum_maturity.rank for claim in candidate.claims):
            return self._decision(candidate, DecisionKind.QUARANTINED, "required closed claim is absent")
        capability = CapabilityToken(
            token_id=digest_object({"candidate": candidate, "issued_at": now}),
            agent_id=candidate.agent_id,
            action=candidate.action,
            scope=candidate.scope,
            intent_digest=candidate.intent_digest,
            issued_at=now,
            expires_at=min(candidate.expires_at, now + self.policy.token_ttl),
            budget=dict(candidate.resource_cost),
        )
        return self._decision(candidate, DecisionKind.ACCEPTED, "policy satisfied", capability)

    def reject_replay(self, candidate: ActionCandidate, now: int) -> AdmissionDecision:
        """Convert a journal replay into a deterministic rejection record."""
        try:
            return self.admit(candidate, now)
        except JournalError:
            candidate_digest = digest_object(candidate)
            decision = AdmissionDecision(
                candidate_id=candidate.candidate_id,
                decision=DecisionKind.REJECTED,
                reason="replayed candidate",
                candidate_digest=candidate_digest,
                decision_digest=digest_object({"candidate_digest": candidate_digest, "reason": "replayed candidate"}),
            )
            return decision
