"""Attack data model shared by prompt libraries, scenarios and reports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Minimum length for a canary token. Canaries are matched as substrings of the
# response, so they must be long enough that a coincidental match on ordinary
# prose is effectively impossible.
MIN_CANARY_LENGTH = 8

# Guardrail: a canary must be a *synthetic* token, never a real credential.
# Rejecting credential-shaped values here stops an author from accidentally
# planting a live secret as a "canary".
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI/Anthropic key", re.compile(r"sk-[A-Za-z0-9_-]{10,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
]


def validate_canary(canary: str) -> str:
    """Validate and normalise a synthetic canary token.

    A canary is an *optional*, probe-specific marker planted in the attack
    prompt whose reappearance in the target's **response** is evidence the
    target exposed it. To keep matches precise and safe, a canary must be:

    * non-empty and a single whitespace-free token,
    * at least :data:`MIN_CANARY_LENGTH` characters (distinctive), and
    * not shaped like a real credential (synthetic only).

    Args:
        canary: The raw canary string from a probe definition.

    Returns:
        The stripped canary.

    Raises:
        ValueError: If the canary violates any of the rules above.
    """
    value = canary.strip()
    if not value:
        raise ValueError("canary must not be empty")
    if len(value) < MIN_CANARY_LENGTH:
        raise ValueError(
            f"canary {value!r} is shorter than {MIN_CANARY_LENGTH} characters; "
            "use a distinctive synthetic token so incidental matches are impossible"
        )
    if any(ch.isspace() for ch in value):
        raise ValueError(f"canary {value!r} must be a single token without whitespace")
    for label, pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(value):
            raise ValueError(
                f"canary {value!r} looks like a real credential ({label}); "
                "canaries must be synthetic, never live secrets"
            )
    return value


@dataclass(frozen=True)
class AttackPrompt:
    """One named, documented attack probe.

    Attributes:
        attack_id: Stable identifier, e.g. ``DI-001``.
        category: One of the five built-in categories.
        name: Human-readable probe label.
        prompt: The literal prompt text sent to the target.
        technique: Short label of the manipulation strategy.
        atlas_id: Primary MITRE ATLAS technique ID (see rtl/evaluation/atlas.py).
        source: ``original`` for in-house probes, otherwise the origin
            (e.g. ``garak``/``pyrit``-adjacent or a named research lineage).
        risk: Baseline severity.attack label (critical/high/medium/low).
        rationale: Why this probe works and what it measures.
        tags: Free-form search tags.
        canary: Optional synthetic token planted in the prompt whose reappearance
            in the *response* is evidence of exposure (see validate_canary).
    """

    attack_id: str
    category: str
    name: str
    prompt: str
    technique: str
    atlas_id: str
    source: str
    risk: str
    rationale: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    canary: str | None = None

    def __post_init__(self) -> None:
        if self.canary is not None:
            object.__setattr__(self, "canary", validate_canary(self.canary))

    def to_dict(self) -> dict[str, object]:
        return {
            "attack_id": self.attack_id,
            "category": self.category,
            "name": self.name,
            "prompt": self.prompt,
            "technique": self.technique,
            "atlas_id": self.atlas_id,
            "source": self.source,
            "risk": self.risk,
            "rationale": self.rationale,
            "tags": list(self.tags),
            "canary": self.canary,
        }


__all__ = ["MIN_CANARY_LENGTH", "AttackPrompt", "validate_canary"]
