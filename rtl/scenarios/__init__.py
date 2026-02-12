"""End-to-end attack scenarios registry.

A scenario is a module exposing ``run_agent_browsing``-style async callables
that return ``list[ProbeResult]``. Register new scenarios here and they are
picked up by ``rtl scan --scenarios`` and the suites.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rtl.scenarios.agent_browsing.scenario import run_agent_browsing
from rtl.scenarios.base import (
    Scenario,
    ScenarioContext,
    ScenarioError,
    ScenarioUnsupported,
    build_probe,
)
from rtl.scenarios.multimodal.scenario import run_multimodal
from rtl.scenarios.rag_poisoning.scenario import run_rag_poisoning

ScenarioCallable = Callable[..., Any]

SCENARIOS: dict[str, ScenarioCallable] = {
    "agent_browsing": run_agent_browsing,
    "rag_poisoning": run_rag_poisoning,
    "multimodal": run_multimodal,
}

SCENARIO_DESCRIPTIONS: dict[str, str] = {
    "agent_browsing": "Agent fetches a poisoned web page containing hidden instructions.",
    "rag_poisoning": "A poisoned document steers a RAG assistant's answer.",
    "multimodal": "Image-embedded instructions (stub — needs vision target).",
}

__all__ = [
    "SCENARIOS",
    "SCENARIO_DESCRIPTIONS",
    "Scenario",
    "ScenarioContext",
    "ScenarioError",
    "ScenarioUnsupported",
    "build_probe",
]
