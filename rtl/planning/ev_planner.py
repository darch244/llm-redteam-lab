"""Expected-Value (EV) Multi-Criteria Adaptive Attack Planner.

Optimizes attack selection via:
  EV = (P(success) * Severity * InfoGain * Novelty * ConfirmationValue) / ExpectedCost
Consumes target capability profiles, attack knowledge graph, and episodic memory.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, cast

from rtl.evaluation.severity import SEVERITY_ORDER, SeverityLevel
from rtl.knowledge.catalog import get_default_knowledge_graph
from rtl.logging import get_logger
from rtl.memory.store import AttackMemory
from rtl.mutation.engine import MutationEngine
from rtl.planning.budget import estimate_tokens
from rtl.planning.models import Observation, PlanState, PlanStep, StopReason
from rtl.profiler.models import CapabilityConfidence, CapabilityName, TargetProfile

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt

log = get_logger("planning.ev_planner")


class CandidateScore:
    """Detailed multi-criteria scoring breakdown for candidate explainability."""

    def __init__(
        self,
        probe: AttackPrompt,
        ev_score: float,
        p_success: float,
        severity_weight: float,
        info_gain: float,
        novelty: float,
        confirmation_value: float,
        cost_weight: float,
        rationale: str,
    ) -> None:
        self.probe = probe
        self.ev_score = ev_score
        self.p_success = p_success
        self.severity_weight = severity_weight
        self.info_gain = info_gain
        self.novelty = novelty
        self.confirmation_value = confirmation_value
        self.cost_weight = cost_weight
        self.rationale = rationale


class ExpectedValuePlanner:
    """Enterprise-grade adaptive planner maximizing security evaluation ROI."""

    name = "ev_adaptive"
    version = "2.0.0"

    def __init__(
        self,
        profile: TargetProfile | None = None,
        memory: AttackMemory | None = None,
        seed: int | None = None,
        max_retries_per_category: int = 3,
    ) -> None:
        self.seed = seed if seed is not None else 42
        self.rng = random.Random(self.seed)
        self.profile = profile or TargetProfile(target_id="target", provider="unknown", model="unknown")
        self.memory = memory or AttackMemory()
        self.akg = get_default_knowledge_graph()
        self.max_retries_per_category = max_retries_per_category
        self._scheduled_ids: set[str] = set()
        self.mutation_engine = MutationEngine(seed=self.seed)
        self.generated_probes: dict[str, AttackPrompt] = {}

    def _next_step_id(self, state: PlanState) -> str:
        count = len(state.steps) + 1
        return f"{state.plan_id}:{count:03d}"

    def score_candidate(self, probe: AttackPrompt, state: PlanState) -> CandidateScore:
        """Score candidate probe using multi-criteria expected value formulation."""
        # 1. Capability Prerequisite Gate: penalize or disqualify incompatible attacks
        if probe.category == "data_exfiltration" and not self.profile.has_capability(
            CapabilityName.TOOL_ACCESS, min_confidence=CapabilityConfidence.SUSPECTED
        ):
            # Target has zero suspected tool access; lower EV dramatically
            cap_modifier = 0.2
        else:
            cap_modifier = 1.0

        # 2. Probability of Success (Bayesian historical prior + AKG bypass bonus)
        base_p = self.memory.calculate_estimated_success_prob(probe.category, probe.technique)

        # AKG Defense Bypass Analysis: does this probe's technique bypass known active defenses?
        mem_summary = self.memory.get_summary()
        bypass_bonus = 1.0
        active_defenses = mem_summary.active_defenses

        if "def:keyword_refusal" in active_defenses and (
            "roleplay" in probe.technique or "encoding" in probe.technique
        ):
            bypass_bonus = 1.35
        if "def:system_prompt_guard" in active_defenses and "authority" in probe.technique:
            bypass_bonus = 1.25

        p_success = min(0.95, base_p * bypass_bonus * cap_modifier)

        # 3. Severity Weight
        sev_score = SEVERITY_ORDER.get(cast(SeverityLevel, probe.risk), SEVERITY_ORDER["medium"])
        severity_weight = max(1.0, float(sev_score))

        # 4. Novelty & Information Gain
        novelty = self.memory.calculate_novelty(probe.category, probe.technique)
        info_gain = 0.9 if novelty > 0.6 else 0.4

        # 5. Confirmation Value: probes carrying synthetic canaries provide deterministic ground truth
        confirmation_value = 1.5 if probe.canary else 1.0

        # 6. Expected Cost Weight
        est_tokens = estimate_tokens(probe.prompt)
        cost_weight = max(1.0, est_tokens / 60.0)

        # 7. Final EV Formula
        ev = (p_success * severity_weight * info_gain * novelty * confirmation_value) / cost_weight

        # Build explainable rationale
        reasons = []
        if bypass_bonus > 1.0:
            reasons.append("bypasses active defenses")
        if probe.canary:
            reasons.append("canary verification value")
        if novelty > 0.7:
            reasons.append("high technique novelty")
        if cap_modifier < 1.0:
            reasons.append("lacks confirmed tool capability")

        explanation = f"EV={ev:.2f} (P={p_success:.2f}, Sev={severity_weight}, Nov={novelty:.2f}"
        if reasons:
            explanation += f" | {', '.join(reasons)}"
        explanation += ")"

        return CandidateScore(
            probe=probe,
            ev_score=ev,
            p_success=p_success,
            severity_weight=severity_weight,
            info_gain=info_gain,
            novelty=novelty,
            confirmation_value=confirmation_value,
            cost_weight=cost_weight,
            rationale=explanation,
        )

    def initial_plan(self, state: PlanState, candidates: list[AttackPrompt]) -> list[PlanStep]:
        self._scheduled_ids.clear()
        initial_steps: list[PlanStep] = []

        # Score all candidates
        scored = [self.score_candidate(p, state) for p in candidates]
        # Sort descending by EV score with seeded jitter for deterministic tie-breaking
        scored.sort(key=lambda cs: cs.ev_score + self.rng.uniform(0, 0.001), reverse=True)

        # Diversified reconnaissance phase: select top candidate per distinct category
        seen_cats: set[str] = set()
        for cs in scored:
            if cs.probe.category not in seen_cats:
                seen_cats.add(cs.probe.category)
                self._scheduled_ids.add(cs.probe.attack_id)
                initial_steps.append(
                    PlanStep(
                        step_id=self._next_step_id(state),
                        probe_id=cs.probe.attack_id,
                        category=cs.probe.category,
                        technique=cs.probe.technique,
                        rationale=f"initial EV-optimized surface probe: {cs.rationale}",
                        est_prompt_tokens=estimate_tokens(cs.probe.prompt),
                        est_max_output_tokens=256,
                    )
                )

        return initial_steps

    def revise(
        self,
        state: PlanState,
        last: Observation,
        candidates: list[AttackPrompt],
    ) -> list[PlanStep]:
        # Consolidate observation into episodic memory
        last_step = next((s for s in state.steps if s.step_id == last.step_id), None)
        if last_step:
            self.memory.record_step(last_step, last, campaign_id=state.plan_id)

        # Filter remaining unscheduled candidates
        remaining = [p for p in candidates if p.attack_id not in self._scheduled_ids]

        # Adaptive mutation synthesis if the previous probe was refused or ambiguous
        mem_summary = self.memory.get_summary()
        if last.verdict.label in ("refused", "ambiguous") and last_step:
            original_probe = next(
                (p for p in candidates if p.attack_id == last_step.probe_id),
                self.generated_probes.get(last_step.probe_id),
            )
            if original_probe and "-m2" not in original_probe.attack_id:
                try:
                    generation = 2 if "-m1" in original_probe.attack_id else 1
                    mutated, _ = self.mutation_engine.mutate(
                        original_probe,
                        active_defenses=mem_summary.active_defenses,
                        generation=generation,
                    )
                    self.generated_probes[mutated.attack_id] = mutated
                    if mutated.attack_id not in self._scheduled_ids:
                        remaining.append(mutated)
                except Exception as exc:
                    log.debug("Mutation generation skipped: %s", exc)

        if not remaining:
            return []

        # Re-score unscheduled candidates with updated episodic memory & defense observations
        scored = [self.score_candidate(p, state) for p in remaining]
        scored.sort(key=lambda cs: cs.ev_score + self.rng.uniform(0, 0.001), reverse=True)

        # Pick highest EV candidate
        best = scored[0]
        self._scheduled_ids.add(best.probe.attack_id)

        # Check if influenced by prior memory
        inf_mems = self.memory.get_influencing_memories(best.probe.category, limit=1)
        influence_note = f" (influenced by {inf_mems[0].entry_id} {inf_mems[0].outcome})" if inf_mems else ""

        step = PlanStep(
            step_id=self._next_step_id(state),
            probe_id=best.probe.attack_id,
            category=best.probe.category,
            technique=best.probe.technique,
            parent_step_id=last.step_id,
            rationale=f"adaptive next-best action: {best.rationale}{influence_note}",
            est_prompt_tokens=estimate_tokens(best.probe.prompt),
            est_max_output_tokens=256,
        )
        return [step]

    def should_stop(self, state: PlanState) -> StopReason | None:
        if len(state.observations) >= len(state.steps) and state.steps:
            return StopReason(
                dimension="plan_complete",
                detail="optimal expected value candidate sequence exhausted",
                turn=len(state.observations),
            )
        return None


__all__ = ["CandidateScore", "ExpectedValuePlanner"]
