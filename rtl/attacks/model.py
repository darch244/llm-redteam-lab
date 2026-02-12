"""Attack data model shared by prompt libraries, scenarios and reports."""

from __future__ import annotations

from dataclasses import dataclass, field


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
        }


__all__ = ["AttackPrompt"]
