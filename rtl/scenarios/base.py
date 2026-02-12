"""Scenario base types.

Scenarios are end-to-end, multi-step attack simulations (unlike single-shot
probes). A scenario callable has the signature::

    async def run(target, *, config=None, out_dir=None) -> list[ProbeResult]

and is registered in ``rtl.scenarios.SCENARIOS``.
"""

from __future__ import annotations

import pathlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from rtl.attacks.model import AttackPrompt
from rtl.evaluation.atlas import techniques_for_scenario
from rtl.reporting.models import ProbeResult


class ScenarioError(Exception):
    """Base class for scenario failures."""


class ScenarioUnsupported(ScenarioError):
    """Raised when a scenario cannot run on the configured target."""


@dataclass
class ScenarioContext:
    """Everything a scenario may need beyond the target."""

    out_dir: pathlib.Path | None = None
    config: dict[str, object] = field(default_factory=dict)


class Scenario(ABC):
    """Base class for scenario definitions (see rtl/scenarios/*/scenario.py)."""

    name: str = "base"
    description: str = ""
    atlas_ids: tuple[str, ...] = ()

    def atlas_metadata(self) -> list[dict[str, object]]:
        return techniques_for_scenario(self.name)

    @abstractmethod
    async def run(self, target: object, context: ScenarioContext) -> list[ProbeResult]:
        """Execute the scenario against ``target`` and return probe results."""


def build_probe(
    name: str,
    prompt: str,
    category: str,
    atlas_id: str,
    technique: str,
    rationale: str,
    *,
    source: str = "original",
    risk: str = "high",
) -> AttackPrompt:
    """Helper to construct a scenario probe with a synthetic attack_id."""
    return AttackPrompt(
        attack_id=f"SC-{category[:3].upper()}-{abs(hash(name)) % 1000:04d}",
        category=category,
        name=name,
        prompt=prompt,
        technique=technique,
        atlas_id=atlas_id,
        source=source,
        risk=risk,
        rationale=rationale,
    )


__all__ = ["Scenario", "ScenarioContext", "ScenarioError", "ScenarioUnsupported", "build_probe"]
