"""Data models for attack strategy composition and prompt mutation."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MutationType(StrEnum):
    """Categorization of automated adversarial prompt mutation primitives."""

    ACADEMIC_FRAMING = "academic_framing"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    BASE64_ENCODING = "base64_encoding"
    ROT13_ENCODING = "rot13_encoding"
    HEX_ENCODING = "hex_encoding"
    AUTHORITY_SPOOFING = "authority_spoofing"
    ROLE_CONFUSION = "role_confusion"
    PAYLOAD_FRAGMENTATION = "payload_fragmentation"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"


class MutationRecord(BaseModel):
    """Immutable audit record of a mutation applied to an attack probe."""

    mutation_id: str
    parent_probe_id: str
    mutation_type: MutationType
    generation: int = Field(ge=1, default=1)
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    original_prompt: str
    mutated_prompt: str
    created_at: datetime = Field(default_factory=_utcnow)


__all__ = [
    "MutationRecord",
    "MutationType",
]
