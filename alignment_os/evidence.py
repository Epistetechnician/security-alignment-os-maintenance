"""Digest-bound evidence proposals and independent review."""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import digest_object
from .models import ClaimEnvelope


@dataclass(frozen=True)
class EvidenceProposal:
    proposal_id: str
    source_digest: str
    validator_id: str
    operator_id: str
    claim: ClaimEnvelope
    observations: tuple[tuple[str, str], ...]
    status: str = "held"

    @property
    def digest(self) -> str:
        return digest_object(self)


class EvidenceRegistry:
    def __init__(self) -> None:
        self._proposals: dict[str, EvidenceProposal] = {}

    def propose(self, proposal: EvidenceProposal) -> EvidenceProposal:
        if proposal.proposal_id in self._proposals:
            raise ValueError("duplicate proposal")
        if proposal.status != "held":
            raise ValueError("new proposals must be held")
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    def independently_accept(self, proposal_id: str, reviewer_id: str, expected_digest: str) -> EvidenceProposal:
        proposal = self._proposals[proposal_id]
        if reviewer_id == proposal.operator_id:
            raise ValueError("operator cannot independently accept")
        if proposal.digest != expected_digest:
            raise ValueError("proposal digest mismatch")
        accepted = EvidenceProposal(
            proposal_id=proposal.proposal_id,
            source_digest=proposal.source_digest,
            validator_id=proposal.validator_id,
            operator_id=proposal.operator_id,
            claim=proposal.claim,
            observations=proposal.observations,
            status="accepted",
        )
        self._proposals[proposal_id] = accepted
        return accepted
