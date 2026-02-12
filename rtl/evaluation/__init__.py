"""Evaluation layer — ATLAS mapping, judging, severity scoring."""

from __future__ import annotations

from rtl.evaluation.atlas import (
    ATLAS_MAP,
    CATEGORY_TO_ATLAS,
    SCENARIO_TO_ATLAS,
    lookup,
    techniques_for_category,
    techniques_for_scenario,
    validate_atlas_id,
)
from rtl.evaluation.judge import Judge, JudgeVerdict
from rtl.evaluation.severity import SEVERITY_ORDER, SeverityResult, score

__all__ = [
    "ATLAS_MAP",
    "CATEGORY_TO_ATLAS",
    "SCENARIO_TO_ATLAS",
    "Judge",
    "JudgeVerdict",
    "SEVERITY_ORDER",
    "SeverityResult",
    "lookup",
    "score",
    "techniques_for_category",
    "techniques_for_scenario",
    "validate_atlas_id",
]
