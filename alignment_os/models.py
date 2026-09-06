"""Typed contracts shared by all foundation components."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .crypto import digest_object


class ActionKind(str, Enum):
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    SPEND = "spend"
    REPLICATE = "replicate"
    SELF_MODIFY = "self_modify"
    EXECUTE = "execute"


class DecisionKind(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class ClaimMaturity(str, Enum):
    STUB = "stub"
    LOCAL = "local"
    ATTESTED = "attested"
    PROVEN = "proven"

    @property
    def rank(self) -> int:
        return {
            ClaimMaturity.STUB: 0,
            ClaimMaturity.LOCAL: 1,
            ClaimMaturity.ATTESTED: 2,
            ClaimMaturity.PROVEN: 3,
        }[self]


@dataclass(frozen=True)
class ClaimEnvelope:
    guarantees: tuple[str, ...]
    assumptions: tuple[str, ...]
    excludes: tuple[str, ...]
    maturity: ClaimMaturity
    trust_roots: tuple[str, ...]
    valid_until: int
    provenance_digest: str

    def __post_init__(self) -> None:
        if self.valid_until < 0:
            raise ValueError("valid_until must be non-negative")
        if not self.provenance_digest or len(self.provenance_digest) != 64:
            raise ValueError("provenance_digest must be a SHA-256 hex digest")

    @property
    def closed(self) -> bool:
        return not set(self.assumptions) - set(self.guarantees)

    def compose(self, other: "ClaimEnvelope") -> "ClaimEnvelope":
        """Compose claims while taking the assurance meet."""
        guarantees = tuple(sorted(set(self.guarantees) | set(other.guarantees)))
        assumptions = tuple(
            sorted((set(self.assumptions) | set(other.assumptions)) - set(guarantees))
        )
        return ClaimEnvelope(
            guarantees=guarantees,
            assumptions=assumptions,
            excludes=tuple(sorted(set(self.excludes) | set(other.excludes))),
            maturity=min(self.maturity, other.maturity, key=lambda item: item.rank),
            trust_roots=tuple(sorted(set(self.trust_roots) | set(other.trust_roots))),
            valid_until=min(self.valid_until, other.valid_until),
            provenance_digest=digest_object({"left": self, "right": other}),
        )


@dataclass(frozen=True)
class ActionCandidate:
    candidate_id: str
    agent_id: str
    intent: str
    action: ActionKind
    scope: str
    payload: Mapping[str, Any]
    resource_cost: Mapping[str, int]
    source_digest: str
    claims: tuple[ClaimEnvelope, ...] = field(default_factory=tuple)
    nonce: int = 0
    expires_at: int = 0
    requests_direct_authority: bool = False

    @property
    def intent_digest(self) -> str:
        return digest_object(
            {
                "agent_id": self.agent_id,
                "intent": self.intent,
                "action": self.action,
                "scope": self.scope,
                "payload": dict(self.payload),
                "nonce": self.nonce,
            }
        )


@dataclass(frozen=True)
class CapabilityToken:
    token_id: str
    agent_id: str
    action: ActionKind
    scope: str
    intent_digest: str
    issued_at: int
    expires_at: int
    budget: Mapping[str, int]


@dataclass(frozen=True)
class AdmissionDecision:
    candidate_id: str
    decision: DecisionKind
    reason: str
    candidate_digest: str
    decision_digest: str
    capability: CapabilityToken | None = None
