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
from rtl.scenarios.conversation_jailbreak.scenario import run_conversation_jailbreak
from rtl.scenarios.memory_poisoning.scenario import run_memory_poisoning
from rtl.scenarios.multimodal.scenario import run_multimodal
from rtl.scenarios.rag_poisoning.scenario import run_rag_poisoning
from rtl.scenarios.tool_poisoning.scenario import run_tool_poisoning

ScenarioCallable = Callable[..., Any]

SCENARIOS: dict[str, ScenarioCallable] = {
    "agent_browsing": run_agent_browsing,
    "rag_poisoning": run_rag_poisoning,
    "multimodal": run_multimodal,
    "conversation_jailbreak": run_conversation_jailbreak,
    "tool_poisoning": run_tool_poisoning,
    "memory_poisoning": run_memory_poisoning,
}

SCENARIO_DESCRIPTIONS: dict[str, str] = {
    "agent_browsing": "Agent fetches a poisoned web page containing hidden instructions.",
    "rag_poisoning": "A poisoned document steers a RAG assistant's answer.",
    "multimodal": "Image-embedded instructions (stub — needs vision target).",
    "conversation_jailbreak": (
        "Bounded multi-turn Crescendo-style escalation with adaptive follow-ups, "
        "full history tracking, and judge/evidence integration."
    ),
    "tool_poisoning": (
        "Agent with poisoned tool descriptions/schemas follows hidden malicious instructions "
        "(AML.T0110 AI Agent Tool Poisoning)."
    ),
    "memory_poisoning": (
        "Poisoned long-term memory/context persists malicious instructions across turns "
        "(AML.T0080 AI Agent Context Poisoning)."
    ),
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
