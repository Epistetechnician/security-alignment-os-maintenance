"""Capability-token verification and single-use resource accounting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import ActionKind, CapabilityToken


@dataclass(frozen=True)
class CapabilityUse:
    token_id: str
    action: ActionKind
    scope: str
    cost: Mapping[str, int]


class CapabilityBroker:
    def __init__(self) -> None:
        self._spent: dict[str, dict[str, int]] = {}

    def consume(self, token: CapabilityToken, use: CapabilityUse, now: int) -> bool:
        if token.token_id != use.token_id or token.action is not use.action or token.scope != use.scope:
            return False
        if now < token.issued_at or now >= token.expires_at:
            return False
        if any(not isinstance(value, int) or value < 0 for value in use.cost.values()):
            return False
        spent = self._spent.setdefault(token.token_id, {})
        for axis, amount in use.cost.items():
            if spent.get(axis, 0) + amount > token.budget.get(axis, 0):
                return False
        for axis, amount in use.cost.items():
            spent[axis] = spent.get(axis, 0) + amount
        return True
