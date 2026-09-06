"""Exact-integer risk decisions; this module never transfers value."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class ReleaseKind(str, Enum):
    REJECTED = "rejected"
    QUARANTINED = "quarantined"
    QUEUED = "queued"
    FROZEN = "frozen"


@dataclass(frozen=True)
class RiskDecision:
    release: ReleaseKind
    reason: str
    reserved: Mapping[str, int]


class StatebookKernel:
    def __init__(self, limits: Mapping[str, int] | None = None) -> None:
        self.limits = dict(limits or {"compute": 1_000, "spend": 0, "replication": 0})

    def decide(self, *, evidence_accepted: bool, requested: Mapping[str, int], challenged: bool = False) -> RiskDecision:
        if not evidence_accepted:
            return RiskDecision(ReleaseKind.FROZEN, "evidence is not independently accepted", {})
        if any(not isinstance(value, int) or value < 0 for value in requested.values()):
            return RiskDecision(ReleaseKind.REJECTED, "resource request is not exact non-negative integer data", {})
        if any(requested.get(axis, 0) > limit for axis, limit in self.limits.items()):
            return RiskDecision(ReleaseKind.REJECTED, "risk budget exceeded", {})
        if challenged:
            return RiskDecision(ReleaseKind.QUARANTINED, "challenge window is open", dict(requested))
        return RiskDecision(ReleaseKind.QUEUED, "accepted for separately authorized release", dict(requested))
