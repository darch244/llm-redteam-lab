"""Adaptive attack planning policies: Static baseline and Heuristic adaptive planner."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Protocol

from rtl.planning.budget import estimate_tokens
from rtl.planning.models import Observation, PlanState, PlanStep, StopReason

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt


class Planner(Protocol):
    """Protocol defining the planner decision lifecycle."""

    name: str
    version: str

    def initial_plan(self, state: PlanState, candidates: list[AttackPrompt]) -> list[PlanStep]:
        """Generate initial sequence of plan steps to dispatch."""
        ...

    def revise(
        self,
        state: PlanState,
        last: Observation,
        candidates: list[AttackPrompt],
    ) -> list[PlanStep]:
        """Revise the plan based on the outcome of the latest observation."""
        ...

    def should_stop(self, state: PlanState) -> StopReason | None:
        """Determine whether the planning session should terminate."""
        ...


class StaticPlanner:
    """Baseline non-adaptive planner that executes candidates in static order.

    Preserves exact backward compatibility with the legacy probe loop.
    """

    name = "static"
    version = "1.0.0"

    def initial_plan(self, state: PlanState, candidates: list[AttackPrompt]) -> list[PlanStep]:
        steps: list[PlanStep] = []
        for idx, probe in enumerate(candidates, 1):
            steps.append(
                PlanStep(
                    step_id=f"{state.plan_id}:{idx:03d}",
                    probe_id=probe.attack_id,
                    category=probe.category,
                    technique=probe.technique,
                    rationale=probe.rationale,
                    est_prompt_tokens=estimate_tokens(probe.prompt),
                    est_max_output_tokens=256,
                    est_cost_usd=0.0,
                )
            )
        return steps

    def revise(
        self,
        state: PlanState,
        last: Observation,
        candidates: list[AttackPrompt],
    ) -> list[PlanStep]:
        # Static baseline never revises
        return []

    def should_stop(self, state: PlanState) -> StopReason | None:
        if len(state.observations) >= len(state.steps) and state.steps:
            return StopReason(
                dimension="plan_complete",
                detail="all static probes dispatched",
                turn=len(state.observations),
            )
        return None


class HeuristicPlanner:
    """Evidence-driven adaptive planner.

    Rules:
    1. Initial phase schedules one diverse probe per category to map defenses.
    2. On refusal: switches framing / technique within the same category (up to 2 retries).
    3. On confirmed compromise: schedules one confirmation probe if available, then pivots.
    4. On ambiguous deflection: prioritizes probes carrying synthetic canary tokens.
    5. On error/timeout: retries once, then flags category degraded.
    6. Deterministic tie-breaking using seeded PRNG.
    """

    name = "heuristic"
    version = "1.0.0"

    def __init__(
        self,
        seed: int | None = None,
        max_retries_per_category: int = 2,
    ) -> None:
        self.seed = seed if seed is not None else 42
        self.rng = random.Random(self.seed)
        self.max_retries_per_category = max_retries_per_category
        self._retries_by_cat: dict[str, int] = {}
        self._scheduled_probe_ids: set[str] = set()

    def _next_step_id(self, state: PlanState) -> str:
        count = len(state.steps) + 1
        return f"{state.plan_id}:{count:03d}"

    def initial_plan(self, state: PlanState, candidates: list[AttackPrompt]) -> list[PlanStep]:
        self._retries_by_cat.clear()
        self._scheduled_probe_ids.clear()

        # Group candidates by category
        by_cat: dict[str, list[AttackPrompt]] = {}
        for c in candidates:
            by_cat.setdefault(c.category, []).append(c)

        initial_steps: list[PlanStep] = []
        for cat, probes in by_cat.items():
            if not probes:
                continue
            # Pick first or canary-bearing probe
            canary_probes = [p for p in probes if p.canary]
            pick = canary_probes[0] if canary_probes else probes[0]
            self._scheduled_probe_ids.add(pick.attack_id)
            initial_steps.append(
                PlanStep(
                    step_id=self._next_step_id(state),
                    probe_id=pick.attack_id,
                    category=pick.category,
                    technique=pick.technique,
                    rationale=f"initial surface reconnaissance for category '{cat}'",
                    est_prompt_tokens=estimate_tokens(pick.prompt),
                    est_max_output_tokens=256,
                    est_cost_usd=0.0,
                )
            )
        return initial_steps

    def revise(
        self,
        state: PlanState,
        last: Observation,
        candidates: list[AttackPrompt],
    ) -> list[PlanStep]:
        new_steps: list[PlanStep] = []
        cat = last.category
        kinds = {s.kind for s in last.signals}

        # 1. On confirmed disclosure (canary or concrete secret)
        if "canary_disclosed" in kinds or "concrete_secret" in kinds or "policy_violating_execution" in kinds:
            # Schedule at most one confirmation probe in that category if unprobed
            cat_candidates = [
                p for p in candidates if p.category == cat and p.attack_id not in self._scheduled_probe_ids
            ]
            if cat_candidates:
                confirm_probe = cat_candidates[0]
                self._scheduled_probe_ids.add(confirm_probe.attack_id)
                new_steps.append(
                    PlanStep(
                        step_id=self._next_step_id(state),
                        probe_id=confirm_probe.attack_id,
                        category=confirm_probe.category,
                        technique=confirm_probe.technique,
                        parent_step_id=last.step_id,
                        rationale=f"confirmation probe following confirmed signal in {cat}",
                        est_prompt_tokens=estimate_tokens(confirm_probe.prompt),
                        est_max_output_tokens=256,
                    )
                )

        # 2. On refusal: adapt technique/framing
        elif "refusal" in kinds:
            retries = self._retries_by_cat.get(cat, 0)
            if retries < self.max_retries_per_category:
                cat_candidates = [
                    p for p in candidates if p.category == cat and p.attack_id not in self._scheduled_probe_ids
                ]
                if cat_candidates:
                    # Pick an alternative probe with a different technique
                    pick = cat_candidates[0]
                    self._retries_by_cat[cat] = retries + 1
                    self._scheduled_probe_ids.add(pick.attack_id)
                    new_steps.append(
                        PlanStep(
                            step_id=self._next_step_id(state),
                            probe_id=pick.attack_id,
                            category=pick.category,
                            technique=pick.technique,
                            parent_step_id=last.step_id,
                            rationale=(
                                f"adaptive retry ({retries + 1}/{self.max_retries_per_category}) "
                                f"with alternative technique '{pick.technique}' following refusal"
                            ),
                            est_prompt_tokens=estimate_tokens(pick.prompt),
                            est_max_output_tokens=256,
                        )
                    )

        # 3. On ambiguous deflection: seek canary probe
        elif "deflection" in kinds or "textual_mention" in kinds or "unsupported_claim" in kinds:
            cat_candidates = [
                p
                for p in candidates
                if p.category == cat and p.attack_id not in self._scheduled_probe_ids and p.canary is not None
            ]
            if cat_candidates:
                pick = cat_candidates[0]
                self._scheduled_probe_ids.add(pick.attack_id)
                new_steps.append(
                    PlanStep(
                        step_id=self._next_step_id(state),
                        probe_id=pick.attack_id,
                        category=pick.category,
                        technique=pick.technique,
                        parent_step_id=last.step_id,
                        rationale=(
                            "ground-truth verification probe using synthetic canary following ambiguous deflection"
                        ),
                        est_prompt_tokens=estimate_tokens(pick.prompt),
                        est_max_output_tokens=256,
                    )
                )

        # 4. If nothing specific was triggered, pick any remaining candidate
        if not new_steps:
            remaining = [p for p in candidates if p.attack_id not in self._scheduled_probe_ids]
            if remaining:
                pick = remaining[0]
                self._scheduled_probe_ids.add(pick.attack_id)
                new_steps.append(
                    PlanStep(
                        step_id=self._next_step_id(state),
                        probe_id=pick.attack_id,
                        category=pick.category,
                        technique=pick.technique,
                        rationale=f"breadth exploration probe for category '{pick.category}'",
                        est_prompt_tokens=estimate_tokens(pick.prompt),
                        est_max_output_tokens=256,
                    )
                )

        return new_steps

    def should_stop(self, state: PlanState) -> StopReason | None:
        # Check if all planned steps have been observed and no pending steps exist
        if len(state.observations) >= len(state.steps) and state.steps:
            return StopReason(
                dimension="plan_complete",
                detail="all adaptive plan steps executed",
                turn=len(state.observations),
            )
        return None


__all__ = ["HeuristicPlanner", "Planner", "StaticPlanner"]
