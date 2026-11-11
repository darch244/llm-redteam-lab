"""Mutation engine orchestrating adversarial prompt transformations and lineage tracking."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from rtl.logging import get_logger
from rtl.mutation.models import MutationRecord, MutationType
from rtl.mutation.strategies import STRATEGIES, BaseMutationStrategy

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt

log = get_logger("mutation.engine")


class MutationEngine:
    """Orchestrator for intelligent adversarial mutation and strategy composition."""

    def __init__(self, seed: int = 42, max_generation: int = 3) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.max_generation = max_generation
        self._records: list[MutationRecord] = []
        self._strategies: dict[MutationType, BaseMutationStrategy] = {mtype: cls() for mtype, cls in STRATEGIES.items()}

    @property
    def records(self) -> list[MutationRecord]:
        """Audit trail of all mutations performed in this session."""
        return list(self._records)

    def recommend_strategies(
        self,
        probe: AttackPrompt,
        active_defenses: list[str] | None = None,
    ) -> list[MutationType]:
        """Recommend optimal mutation types based on active defenses and probe characteristics."""
        defenses = set(active_defenses or [])
        recommendations: list[MutationType] = []

        if "def:keyword_refusal" in defenses:
            recommendations.extend(
                [
                    MutationType.BASE64_ENCODING,
                    MutationType.ACADEMIC_FRAMING,
                    MutationType.ROT13_ENCODING,
                ]
            )
        if "def:system_prompt_guard" in defenses:
            recommendations.extend(
                [
                    MutationType.AUTHORITY_SPOOFING,
                    MutationType.ROLE_CONFUSION,
                ]
            )
        if "def:tool_execution_boundary" in defenses:
            recommendations.extend(
                [
                    MutationType.HYPOTHETICAL_FRAMING,
                    MutationType.PAYLOAD_FRAGMENTATION,
                ]
            )

        # Default fallbacks if no specific defense active
        if not recommendations:
            recommendations = [
                MutationType.ACADEMIC_FRAMING,
                MutationType.BASE64_ENCODING,
                MutationType.AUTHORITY_SPOOFING,
                MutationType.HYPOTHETICAL_FRAMING,
            ]

        # Deduplicate while preserving priority order
        seen: set[MutationType] = set()
        deduped: list[MutationType] = []
        for r in recommendations:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    def mutate(
        self,
        probe: AttackPrompt,
        mutation_type: MutationType | None = None,
        generation: int = 1,
        active_defenses: list[str] | None = None,
    ) -> tuple[AttackPrompt, MutationRecord]:
        """Apply a mutation to an attack probe and record the lineage."""
        if generation > self.max_generation:
            raise ValueError(
                f"Generation {generation} exceeds maximum permitted mutation depth ({self.max_generation})"
            )

        if mutation_type is None:
            recommended = self.recommend_strategies(probe, active_defenses)
            mutation_type = recommended[0]

        strategy = self._strategies.get(mutation_type)
        if not strategy:
            raise KeyError(f"Unknown mutation strategy '{mutation_type}'")

        mutated_probe, record = strategy.mutate(probe, generation=generation)
        self._records.append(record)
        log.info(
            "Mutated probe %s -> %s via %s (gen %d)",
            probe.attack_id,
            mutated_probe.attack_id,
            mutation_type.value,
            generation,
        )
        return mutated_probe, record


__all__ = ["MutationEngine"]
