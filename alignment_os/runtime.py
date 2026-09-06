"""Local bounded state execution after admission."""

from __future__ import annotations

from .crypto import digest_object
from .capabilities import CapabilityBroker, CapabilityUse
from .models import ActionCandidate, AdmissionDecision, DecisionKind


class RuntimeErrorBoundary(RuntimeError):
    pass


class GuardedRuntime:
    def __init__(self, kernel, broker: CapabilityBroker | None = None) -> None:
        self.kernel = kernel
        self.broker = broker or CapabilityBroker()
        self.state: dict[str, object] = {}
        self.audit: list[dict[str, object]] = []
        self._killed = False

    def kill(self, reason: str) -> None:
        self._killed = True
        self.audit.append({"event": "kill", "reason": reason})

    @property
    def killed(self) -> bool:
        return self._killed

    def execute(self, candidate: ActionCandidate, decision: AdmissionDecision, now: int) -> bool:
        if self._killed:
            raise RuntimeErrorBoundary("runtime is killed")
        if decision.decision is not DecisionKind.ACCEPTED or decision.capability is None:
            return False
        token = decision.capability
        if token.agent_id != candidate.agent_id or token.intent_digest != candidate.intent_digest:
            raise RuntimeErrorBoundary("capability does not bind to candidate")
        if token.expires_at <= now:
            raise RuntimeErrorBoundary("capability expired")
        if candidate.action.value == "read":
            self.audit.append({"event": "read", "candidate": candidate.candidate_id, "state_digest": digest_object(self.state)})
            return True
        if candidate.action.value == "write":
            key = candidate.payload.get("key")
            if not isinstance(key, str) or not key.startswith(f"{token.scope}:"):
                raise RuntimeErrorBoundary("write target outside capability scope")
        if not self.broker.consume(
            token,
            CapabilityUse(token.token_id, candidate.action, token.scope, candidate.resource_cost),
            now,
        ):
            raise RuntimeErrorBoundary("capability budget exhausted or invalid")
        if candidate.action.value == "write":
            self.state[key] = candidate.payload.get("value")
            self.audit.append({"event": "write", "candidate": candidate.candidate_id, "key": key, "state_digest": digest_object(self.state)})
            return True
        raise RuntimeErrorBoundary("unsupported runtime action")
