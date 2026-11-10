"""Target capability profiling models.

Tracks target architectural traits (tools, memory, vision, RAG, guardrails)
with evidentiary confidence ratings: known, observed, inferred, suspected, unknown.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CapabilityName(StrEnum):
    """Enumeration of recognizable target system capabilities."""

    TOOL_ACCESS = "tool_access"
    FUNCTION_CALLING = "function_calling"
    BROWSER_ACCESS = "browser_access"
    RAG = "rag"
    MEMORY = "memory"
    VISION = "vision"
    AUDIO = "audio"
    MULTIMODAL = "multimodal"
    AGENTIC_EXECUTION = "agentic_execution"
    RETRIEVAL = "retrieval"
    CODE_EXECUTION = "code_execution"
    EXTERNAL_NETWORK = "external_network"
    SYSTEM_PROMPT_VISIBILITY = "system_prompt_visibility"
    STRUCTURED_OUTPUT = "structured_output"
    GUARDRAILS = "guardrails"
    CONTEXT_WINDOW = "context_window"


class CapabilityConfidence(StrEnum):
    """Evidentiary confidence ranking for an observed capability."""

    UNKNOWN = "unknown"
    SUSPECTED = "suspected"
    INFERRED = "inferred"
    OBSERVED = "observed"
    KNOWN = "known"


# Numeric order for confidence comparisons
_CONFIDENCE_LEVELS: dict[CapabilityConfidence, int] = {
    CapabilityConfidence.UNKNOWN: 0,
    CapabilityConfidence.SUSPECTED: 1,
    CapabilityConfidence.INFERRED: 2,
    CapabilityConfidence.OBSERVED: 3,
    CapabilityConfidence.KNOWN: 4,
}


class CapabilityEntry(BaseModel):
    """A single capability assessment for a target."""

    name: CapabilityName
    confidence: CapabilityConfidence = CapabilityConfidence.UNKNOWN
    evidence_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=_utcnow)


class TargetProfile(BaseModel):
    """Dynamic capability and defense profile of an evaluated AI system."""

    target_id: str
    provider: str
    model: str
    capabilities: dict[str, CapabilityEntry] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Initialize default entries if not already present
        for cap in CapabilityName:
            if cap.value not in self.capabilities:
                self.capabilities[cap.value] = CapabilityEntry(name=cap)

    def record_evidence(
        self,
        name: CapabilityName | str,
        confidence: CapabilityConfidence,
        evidence_id: str | None = None,
        note: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CapabilityEntry:
        """Update a capability assessment if the new evidence level meets or exceeds the current."""
        cap_key = name.value if isinstance(name, CapabilityName) else name
        entry = self.capabilities.get(cap_key)
        if not entry:
            cap_enum = CapabilityName(cap_key)
            entry = CapabilityEntry(name=cap_enum)
            self.capabilities[cap_key] = entry

        current_level = _CONFIDENCE_LEVELS.get(entry.confidence, 0)
        new_level = _CONFIDENCE_LEVELS.get(confidence, 0)

        # Monotonically upgrade or corroborate
        if new_level >= current_level:
            entry.confidence = confidence

        if evidence_id and evidence_id not in entry.evidence_ids:
            entry.evidence_ids.append(evidence_id)
        if note:
            entry.notes.append(note)
        if metadata:
            entry.metadata.update(metadata)

        entry.updated_at = _utcnow()
        self.updated_at = _utcnow()
        return entry

    def has_capability(
        self,
        name: CapabilityName | str,
        min_confidence: CapabilityConfidence = CapabilityConfidence.INFERRED,
    ) -> bool:
        """Check if a capability is present at or above a minimum evidentiary threshold."""
        cap_key = name.value if isinstance(name, CapabilityName) else name
        entry = self.capabilities.get(cap_key)
        if not entry:
            return False
        return _CONFIDENCE_LEVELS.get(entry.confidence, 0) >= _CONFIDENCE_LEVELS.get(min_confidence, 2)


__all__ = [
    "CapabilityConfidence",
    "CapabilityEntry",
    "CapabilityName",
    "TargetProfile",
]
