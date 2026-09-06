"""Deterministic semantic cases for the foundation security benchmark."""

from __future__ import annotations

from dataclasses import dataclass

from .admission import AdmissionKernel
from .crypto import digest_object
from .models import ActionCandidate, ActionKind, ClaimEnvelope, ClaimMaturity, DecisionKind
from .runtime import GuardedRuntime


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    candidate: ActionCandidate
    expected: DecisionKind


@dataclass(frozen=True)
class BenchmarkResult:
    name: str
    expected: DecisionKind
    actual: DecisionKind
    state_changed: bool

    @property
    def passed(self) -> bool:
        return self.expected is self.actual and (self.actual is DecisionKind.ACCEPTED or not self.state_changed)


def _claim() -> ClaimEnvelope:
    return ClaimEnvelope(
        guarantees=("PolicyCompliance",),
        assumptions=(),
        excludes=("semantic_correctness", "production_readiness"),
        maturity=ClaimMaturity.LOCAL,
        trust_roots=("local_validator",),
        valid_until=100,
        provenance_digest="a" * 64,
    )


def cases() -> tuple[BenchmarkCase, ...]:
    common = {
        "agent_id": "agent-1",
        "scope": "sandbox",
        "payload": {"key": "sandbox:flag", "value": True},
        "resource_cost": {"cpu_ms": 10, "bytes": 10, "spend": 0},
        "source_digest": "b" * 64,
        "claims": (_claim(),),
        "expires_at": 50,
    }
    valid = ActionCandidate(candidate_id="valid-write", intent="set safe flag", action=ActionKind.WRITE, **common)
    direct = ActionCandidate(candidate_id="direct-authority", intent="become admin", action=ActionKind.WRITE, requests_direct_authority=True, **common)
    missing = ActionCandidate(candidate_id="missing-source", intent="read", action=ActionKind.READ, source_digest="", **{key: value for key, value in common.items() if key != "source_digest"})
    over_budget = ActionCandidate(candidate_id="over-budget", intent="expensive", action=ActionKind.WRITE, resource_cost={"cpu_ms": 10_000}, **{key: value for key, value in common.items() if key != "resource_cost"})
    expired = ActionCandidate(candidate_id="expired", intent="late", action=ActionKind.READ, expires_at=1, **{key: value for key, value in common.items() if key != "expires_at"})
    return (
        BenchmarkCase("valid_write", valid, DecisionKind.ACCEPTED),
        BenchmarkCase("direct_authority", direct, DecisionKind.REJECTED),
        BenchmarkCase("missing_source", missing, DecisionKind.QUARANTINED),
        BenchmarkCase("over_budget", over_budget, DecisionKind.REJECTED),
        BenchmarkCase("expired", expired, DecisionKind.REJECTED),
    )


def run() -> tuple[BenchmarkResult, ...]:
    results: list[BenchmarkResult] = []
    for case in cases():
        kernel = AdmissionKernel()
        runtime = GuardedRuntime(kernel)
        before = digest_object(runtime.state)
        decision = kernel.admit(case.candidate, now=10)
        if decision.decision is DecisionKind.ACCEPTED:
            runtime.execute(case.candidate, decision, now=10)
        changed = before != digest_object(runtime.state)
        results.append(BenchmarkResult(case.name, case.expected, decision.decision, changed))
    return tuple(results)
