"""Bounded episodic attack memory store with information-gain tracking."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rtl.logging import get_logger
from rtl.memory.models import AttackMemoryEntry, MemoryOutcome, MemorySummary

if TYPE_CHECKING:
    from rtl.planning.models import Observation, PlanStep

log = get_logger("memory.store")


class AttackMemory:
    """Bounded, queryable episodic memory tracking target responses and defense behaviors."""

    def __init__(self, max_entries: int = 500) -> None:
        self.max_entries = max_entries
        self.entries: list[AttackMemoryEntry] = []
        self._technique_counts: dict[str, int] = {}
        self._category_successes: dict[str, int] = {}
        self._category_attempts: dict[str, int] = {}
        self._known_defenses: set[str] = set()

    def record_step(
        self,
        step: PlanStep,
        observation: Observation,
        evidence_ids: list[str] | None = None,
        campaign_id: str = "default_campaign",
    ) -> AttackMemoryEntry:
        """Consolidate an executed step and its observation into episodic memory."""
        # 1. Determine normalized outcome
        verdict = observation.verdict
        signals: list[str] = [str(s.kind) for s in observation.signals]

        outcome = MemoryOutcome.AMBIGUOUS
        if observation.error_class:
            outcome = MemoryOutcome.ERROR
        elif "blocked_tool_call" in signals:
            outcome = MemoryOutcome.BLOCKED
        elif verdict.label == "refused":
            outcome = MemoryOutcome.REFUSED
        elif verdict.success:
            outcome = MemoryOutcome.SUCCESS

        # 2. Extract observed defenses
        defenses: list[str] = []
        if outcome == MemoryOutcome.REFUSED:
            defenses.append("def:keyword_refusal")
            self._known_defenses.add("def:keyword_refusal")
        if "blocked_tool_call" in signals:
            defenses.append("def:tool_execution_boundary")
            self._known_defenses.add("def:tool_execution_boundary")
        if "withheld" in verdict.reason.lower():
            defenses.append("def:system_prompt_guard")
            self._known_defenses.add("def:system_prompt_guard")

        # 3. Calculate information gain: novel outcomes yield higher information
        tech_key = f"{step.category}:{step.technique}"
        prior_tech_attempts = self._technique_counts.get(tech_key, 0)
        self._technique_counts[tech_key] = prior_tech_attempts + 1

        self._category_attempts[step.category] = self._category_attempts.get(step.category, 0) + 1
        if outcome == MemoryOutcome.SUCCESS:
            self._category_successes[step.category] = self._category_successes.get(step.category, 0) + 1

        # Information gain degrades with redundant outcomes on the same technique
        if prior_tech_attempts == 0:
            info_gain = 1.0  # First time testing technique
        elif outcome == MemoryOutcome.SUCCESS:
            info_gain = 0.9  # Confirmed compromise always carries high value
        elif outcome == MemoryOutcome.REFUSED:
            # Diminishing returns on repeated refusals of identical technique
            info_gain = max(0.1, round(1.0 / (prior_tech_attempts + 1), 2))
        else:
            info_gain = 0.5

        entry = AttackMemoryEntry(
            entry_id=f"mem-{len(self.entries) + 1:04d}",
            campaign_id=campaign_id,
            attack_id=step.probe_id,
            category=step.category,
            technique=step.technique,
            outcome=outcome,
            confidence=verdict.confidence,
            signals=signals,
            evidence_refs=list(evidence_ids or []),
            defenses_encountered=defenses,
            information_gain=info_gain,
        )

        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            # Bounded memory: pop oldest entry
            self.entries.pop(0)

        return entry

    def calculate_novelty(self, category: str, technique: str) -> float:
        """Compute novelty score in [0.1, 1.0]. Less frequently tested techniques score higher."""
        key = f"{category}:{technique}"
        count = self._technique_counts.get(key, 0)
        return max(0.1, round(1.0 / (1.0 + count * 0.5), 3))

    def calculate_estimated_success_prob(self, category: str, technique: str) -> float:
        """Estimate prior success probability based on episodic track record."""
        attempts = self._category_attempts.get(category, 0)
        successes = self._category_successes.get(category, 0)

        key = f"{category}:{technique}"
        # If this exact technique has failed repeatedly, reduce probability
        tech_attempts = self._technique_counts.get(key, 0)
        has_failed = tech_attempts > 0 and successes == 0

        if has_failed:
            return max(0.05, 0.3 / (tech_attempts + 1))

        if attempts > 0:
            # Bayesian smoothed probability
            return (successes + 1.0) / (attempts + 2.0)

        return 0.35  # Neutral default prior

    def get_influencing_memories(self, category: str, limit: int = 3) -> list[AttackMemoryEntry]:
        """Retrieve recent relevant memories in category that inform planner choices."""
        matching = [e for e in reversed(self.entries) if e.category == category]
        for e in matching[:limit]:
            e.influence_count += 1
        return matching[:limit]

    def get_summary(self) -> MemorySummary:
        """Compute situational awareness overview across memory history."""
        success_rates = {}
        for cat, att in self._category_attempts.items():
            succ = self._category_successes.get(cat, 0)
            success_rates[cat] = round(succ / att, 3) if att > 0 else 0.0

        return MemorySummary(
            total_attempts=len(self.entries),
            successful_attempts=sum(1 for e in self.entries if e.outcome == MemoryOutcome.SUCCESS),
            refused_attempts=sum(1 for e in self.entries if e.outcome == MemoryOutcome.REFUSED),
            blocked_attempts=sum(1 for e in self.entries if e.outcome == MemoryOutcome.BLOCKED),
            category_success_rates=success_rates,
            technique_failure_counts=dict(self._technique_counts),
            active_defenses=sorted(self._known_defenses),
        )


__all__ = ["AttackMemory"]
