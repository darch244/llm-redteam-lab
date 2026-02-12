"""MITRE ATLAS technique mapping.

Technique IDs and sub-technique structure follow official MITRE ATLAS data
(https://atlas.mitre.org). The mappings below are maintained for reporting
convenience and to power the severity model; tactic assignments are
best-effort where ATLAS does not publish a tactic column for a technique.
"""

from __future__ import annotations

from typing import Any

ATLAS_MAP: dict[str, dict[str, Any]] = {
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "parent": None,
        "tactic": "AI Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0043",
        "description": "An adversary crafts adversarial inputs to exploit ML model behaviour.",
    },
    "AML.T0024": {
        "name": "Exfiltration via AI Inference API",
        "parent": None,
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0024",
        "description": "An adversary exfiltrates private information by querying an AI inference API.",
    },
    "AML.T0024.000": {
        "name": "Infer Training Data Membership",
        "parent": "AML.T0024",
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0024.000",
        "description": "Membership-inference over the model to learn whether data was in training.",
    },
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "parent": None,
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
        "description": "Malicious prompts cause the LLM to act in unintended ways.",
    },
    "AML.T0051.000": {
        "name": "Direct Prompt Injection",
        "parent": "AML.T0051",
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0051.000",
        "description": "The adversary injects instructions directly into the model's input.",
    },
    "AML.T0051.001": {
        "name": "Indirect Prompt Injection",
        "parent": "AML.T0051",
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0051.001",
        "description": "Malicious prompts ingested from a separate data channel (docs, web pages, DB).",
    },
    "AML.T0051.002": {
        "name": "Triggered Prompt Injection",
        "parent": "AML.T0051",
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0051.002",
        "description": "An injection triggered by a user action or event — typical of AI agents.",
    },
    "AML.T0054": {
        "name": "LLM Jailbreak",
        "parent": None,
        "tactic": "Defense Evasion",
        "url": "https://atlas.mitre.org/techniques/AML.T0054",
        "description": "Prompts engineered to bypass the model's safety alignment.",
    },
    "AML.T0056": {
        "name": "Extract LLM System Prompt",
        "parent": None,
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0056",
        "description": "Recovering the system prompt / meta-instructions that configure an LLM application.",
    },
    "AML.T0057": {
        "name": "LLM Data Leakage",
        "parent": None,
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0057",
        "description": "Unintended disclosure of private data through LLM responses.",
    },
    "AML.T0070": {
        "name": "RAG Poisoning",
        "parent": None,
        "tactic": "Persistence",
        "url": "https://atlas.mitre.org/techniques/AML.T0070",
        "description": "Adversarial content injected into a RAG knowledge base to corrupt retrieval.",
    },
    "AML.T0080": {
        "name": "AI Agent Context Poisoning",
        "parent": None,
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0080",
        "description": "Poisoning the working context (memory/thread) of an AI agent.",
    },
    "AML.T0086": {
        "name": "Exfiltration via AI Agent Tool Invocation",
        "parent": None,
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0086",
        "description": "Abusing an agent's tools (email, HTTP fetch, DB) to move data out.",
    },
    "AML.T0110": {
        "name": "AI Agent Tool Poisoning",
        "parent": None,
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0110",
        "description": "Malicious definitions/instructions planted inside an agent's tooling.",
    },
}

CATEGORY_TO_ATLAS: dict[str, list[str]] = {
    "direct_injection": ["AML.T0051.000", "AML.T0051"],
    "indirect_injection": ["AML.T0051.001", "AML.T0051"],
    "jailbreak": ["AML.T0054"],
    "system_prompt_extraction": ["AML.T0056", "AML.T0051.000"],
    "data_exfiltration": ["AML.T0057", "AML.T0024", "AML.T0024.000"],
}

SCENARIO_TO_ATLAS: dict[str, list[str]] = {
    "agent_browsing": ["AML.T0051.001", "AML.T0051.002", "AML.T0054"],
    "rag_poisoning": ["AML.T0070", "AML.T0051.001"],
    "multimodal": ["AML.T0051.001", "AML.T0043"],
}

KNOWN_ATLAS_IDS = frozenset(ATLAS_MAP)


def validate_atlas_id(technique_id: str) -> bool:
    """Return True when ``technique_id`` is a known ATLAS technique or sub-technique."""
    return technique_id in KNOWN_ATLAS_IDS


def lookup(technique_id: str) -> dict[str, Any] | None:
    """Return ATLAS metadata for a technique ID (or None)."""
    return ATLAS_MAP.get(technique_id)


def techniques_for_category(category: str) -> list[dict[str, Any]]:
    """Full metadata rows for the techniques a category maps to."""
    return [_row(tech_id) for tech_id in CATEGORY_TO_ATLAS.get(category, [])]


def techniques_for_scenario(scenario: str) -> list[dict[str, Any]]:
    """Full metadata rows for the techniques a scenario maps to."""
    return [_row(tech_id) for tech_id in SCENARIO_TO_ATLAS.get(scenario, [])]


def _row(technique_id: str) -> dict[str, Any]:
    meta = ATLAS_MAP.get(technique_id)
    if meta is None:
        return {"id": technique_id, "name": technique_id, "tactic": "Unknown"}
    return {"id": technique_id, **meta}


__all__ = [
    "ATLAS_MAP",
    "CATEGORY_TO_ATLAS",
    "SCENARIO_TO_ATLAS",
    "lookup",
    "techniques_for_category",
    "techniques_for_scenario",
    "validate_atlas_id",
]
