"""Structured episodic attack memory data models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MemoryOutcome(StrEnum):
    """Normalized result of an attack attempt for memory consolidation."""

    SUCCESS = "success"
    REFUSED = "refused"
    AMBIGUOUS = "ambiguous"
    BLOCKED = "blocked"
    ERROR = "error"


class AttackMemoryEntry(BaseModel):
    """An immutable, structured record of an evaluated attack attempt."""

    entry_id: str
    campaign_id: str
    attack_id: str
    category: str
    technique: str
    outcome: MemoryOutcome
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    defenses_encountered: list[str] = Field(default_factory=list)
    information_gain: float = Field(default=0.5, ge=0.0, le=1.0)
    influence_count: int = Field(default=0, ge=0)
    timestamp: datetime = Field(default_factory=_utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MemorySummary(BaseModel):
    """Consolidated situational awareness derived from episodic memory."""

    total_attempts: int = 0
    successful_attempts: int = 0
    refused_attempts: int = 0
    blocked_attempts: int = 0
    category_success_rates: dict[str, float] = Field(default_factory=dict)
    technique_failure_counts: dict[str, int] = Field(default_factory=dict)
    active_defenses: list[str] = Field(default_factory=list)


__all__ = [
    "AttackMemoryEntry",
    "MemoryOutcome",
    "MemorySummary",
]
