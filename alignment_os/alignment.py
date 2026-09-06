"""Alignment measurement contracts without model execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CausalMeasurementSpec:
    protocol_id: str
    estimand: str
    fit_families: int
    tune_families: int
    assessment_families: int
    held_out_required: bool = True
    model_execution_authorized: bool = False


@dataclass(frozen=True)
class PredictionLock:
    protocol_id: str
    signs: tuple[int, ...]
    controls_passed: bool
    independent_accept: bool

    def assessment_eligible(self) -> bool:
        return bool(self.signs) and self.controls_passed and self.independent_accept and all(sign in (-1, 1) for sign in self.signs)


def current_foundation_spec() -> CausalMeasurementSpec:
    return CausalMeasurementSpec(
        protocol_id="security-alignment-os-foundation-v1-alignment-contract",
        estimand="held-out causal intervention effect on a declared behavioral target",
        fit_families=0,
        tune_families=0,
        assessment_families=0,
    )
