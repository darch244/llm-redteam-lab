"""Adaptive attack-planning engine orchestrator.

Glues the planner, budget ledger, replay recorder, evidence graph,
confirmation engine, target profiler, and verdict policy.
Enforces all core invariants (INV-1 through INV-5).
"""

from __future__ import annotations

import hashlib
import time
from typing import TYPE_CHECKING, Any

from rtl.core.confirmation import ConfirmationEngine
from rtl.core.evidence_graph import EdgeType, EvidenceGraph, NodeType
from rtl.evaluation.judge import Judge
from rtl.evaluation.severity import score as severity_score
from rtl.evaluation.verdict_policy import VerdictPolicy
from rtl.logging import get_logger
from rtl.planning.budget import BudgetExceeded, BudgetLedger, estimate_tokens
from rtl.planning.ev_planner import ExpectedValuePlanner
from rtl.planning.evidence import extract_signals
from rtl.planning.models import (
    BudgetLimits,
    BudgetUsage,
    Observation,
    PlanState,
    ReplayEvent,
    ReplayManifest,
    StopReason,
)
from rtl.planning.policy import HeuristicPlanner, Planner, StaticPlanner
from rtl.planning.replay import ReplayRecorder
from rtl.profiler.detector import PassiveProfiler
from rtl.profiler.models import TargetProfile
from rtl.reporting.models import Finding, ProbeResult

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt
    from rtl.config import ScanOptions
    from rtl.targets.base import Target

log = get_logger("planning.engine")


class AdaptiveEngine:
    """Bounded, evidence-driven adaptive red teaming engine."""

    def __init__(
        self,
        options: ScanOptions,
        target: Target,
        probes: list[AttackPrompt],
        verdict_policy: VerdictPolicy | None = None,
        target_profile: TargetProfile | None = None,
    ) -> None:
        self.options = options
        self.target = target
        self.probes = probes
        self.probe_map = {p.attack_id: p for p in probes}
        if verdict_policy is None:
            judge_target = None
            if options.judge and options.judge.mode in ("auto", "llm") and options.judge.model:
                from rtl.config import TargetConfig

                judge_target = TargetConfig.parse(options.judge.model).build_target()
            judge = Judge(judge_target=judge_target, mode=options.judge.mode if options.judge else "auto")
            verdict_policy = VerdictPolicy(judge)
        self.verdict_policy = verdict_policy
        self.target_fp = target.fingerprint()

        self.limits = options.budget or BudgetLimits()
        self.ledger = BudgetLedger(self.limits)
        self.plan_id = f"plan-s{options.seed}" if options.seed is not None else f"plan-{int(time.time())}"
        self.state = PlanState(
            plan_id=self.plan_id,
            limits=self.limits,
            objective="adversarial_resilience_audit",
        )

        # 1. Target Profile
        provider = self.target_fp.get("provider", target.provider)
        model = self.target_fp.get("model", target.model)
        self.profile = target_profile or TargetProfile(
            target_id=f"{provider}:{model}",
            provider=provider,
            model=model,
        )

        # 2. Select Planning Strategy
        planner: Planner
        if options.planner == "ev_adaptive":
            planner = ExpectedValuePlanner(profile=self.profile, seed=options.seed)
        elif options.adaptive or options.planner in ("heuristic", "adaptive"):
            planner = HeuristicPlanner(seed=options.seed)
        else:
            planner = StaticPlanner()
        self.planner = planner

        # 3. Initialize First-Class Evidence DAG
        self.evidence_graph = EvidenceGraph()
        self.target_node = self.evidence_graph.add_node(
            NodeType.TARGET,
            payload=self.target_fp,
            custom_id=f"target-{provider}-{model}",
        )
        self.campaign_node = self.evidence_graph.add_node(
            NodeType.CAMPAIGN,
            payload={"suite": options.suite.name, "planner": self.planner.name, "seed": options.seed},
            parent_ids=[self.target_node.id],
            edge_type=EdgeType.TARGETS,
            custom_id=f"campaign-{self.plan_id}",
        )

        # 4. Audit Manifest Recorder
        self.recorder = ReplayRecorder(
            planner_name=self.planner.name,
            planner_version=self.planner.version,
            seed=options.seed if options.seed is not None else 42,
            suite=options.suite,
            probes=self.probes,
            limits=self.limits,
            judge_mode=options.judge.mode,
            target_fingerprint=self.target_fp,
            redacted=options.redact,
        )

    async def run(self) -> tuple[list[Finding], PlanState, ReplayManifest]:
        """Execute the planned attack sequence within budget bounds."""
        initial_steps = self.planner.initial_plan(self.state, self.probes)
        self.state.steps.extend(initial_steps)
        log.info("initial plan steps scheduled: %d", len(initial_steps))

        findings: list[Finding] = []
        cursor = 0

        while cursor < len(self.state.steps):
            # Check stopping criteria
            stop = self.planner.should_stop(self.state)
            if stop is not None:
                self.state.stop_reason = stop
                log.info("planner signaled stop: %s (%s)", stop.dimension, stop.detail)
                break

            step = self.state.steps[cursor]
            cursor += 1

            probe = self.probe_map.get(step.probe_id)
            if probe is None:
                log.warning("unknown probe %s in plan; skipping", step.probe_id)
                continue

            # Check and reserve budget before dispatch
            try:
                reservation = self.ledger.reserve(step)
            except BudgetExceeded as exc:
                log.warning("budget limit hit: %s", exc)
                self.state.stop_reason = StopReason(
                    dimension=exc.dimension,
                    detail=str(exc),
                    turn=len(self.state.observations),
                )
                break

            # Prepare effective prompt
            prompt = probe.prompt
            effective_prompt: str | None = None
            if self.options.max_prompt_len and len(prompt) > self.options.max_prompt_len:
                prompt = prompt[: self.options.max_prompt_len]
                effective_prompt = prompt

            # Record attempt in Evidence Graph
            attempt_node = self.evidence_graph.add_node(
                NodeType.ATTEMPT,
                payload={
                    "step_id": step.step_id,
                    "probe_id": step.probe_id,
                    "category": step.category,
                    "technique": step.technique,
                    "rationale": step.rationale,
                },
                parent_ids=[self.campaign_node.id],
                edge_type=EdgeType.EXECUTES,
            )

            # Dispatch to target
            t0 = time.monotonic()
            response = ""
            error: str | None = None
            try:
                response = await self.target.asend(prompt)
            except Exception as exc:
                error = str(exc)
                log.warning("probe %s failed on target: %s", step.probe_id, exc)

            elapsed = max(0.001, time.monotonic() - t0)

            # Record response in Evidence Graph
            response_node = self.evidence_graph.add_node(
                NodeType.RESPONSE,
                payload={"response_excerpt": response[:300], "elapsed_seconds": elapsed, "error": error},
                parent_ids=[attempt_node.id],
                edge_type=EdgeType.PRODUCES,
            )

            # Reconcile budget usage
            actual_prompt_tokens = estimate_tokens(prompt)
            actual_output_tokens = estimate_tokens(response)
            actual_usage = BudgetUsage(
                probes=1,
                turns=1,
                prompt_tokens=actual_prompt_tokens,
                output_tokens=actual_output_tokens,
                cost_usd=0.0,
                tool_calls=0,
                elapsed_seconds=elapsed,
            )
            self.ledger.commit(reservation, actual_usage)

            # Build probe result & evaluate
            probe_result = ProbeResult(
                probe=probe,
                response=response,
                effective_prompt=effective_prompt,
                elapsed_seconds=elapsed,
                error=error,
                skipped=bool(error and not response),
            )

            verdict = self.verdict_policy.evaluate(probe_result, prompt=effective_prompt)
            severity = severity_score(probe, verdict)

            # Extract signals & record observation
            signals = extract_signals(
                verdict,
                raw=probe_result.raw,
                category=probe.category,
                error=error,
            )
            observation = Observation(
                step_id=step.step_id,
                probe_id=step.probe_id,
                category=step.category,
                verdict=verdict,
                signals=signals,
                response_excerpt=response[:300],
                error_class=type(error).__name__ if error else None,
                usage=actual_usage,
                elapsed_seconds=elapsed,
            )
            self.state.observations.append(observation)

            # Update Target Capability Profile passively from observations
            PassiveProfiler.update_from_observation(self.profile, observation, probe_result.raw)

            # Record Observation in Evidence Graph
            obs_node = self.evidence_graph.add_node(
                NodeType.OBSERVATION,
                payload={"signals": [s.kind for s in signals], "error_class": observation.error_class},
                parent_ids=[response_node.id],
                edge_type=EdgeType.OBSERVES,
            )

            # Record Judge decision in Evidence Graph
            judge_node = self.evidence_graph.add_node(
                NodeType.JUDGE_DECISION,
                payload={"label": verdict.label, "confidence": verdict.confidence, "reason": verdict.reason},
                parent_ids=[obs_node.id],
                edge_type=EdgeType.EVALUATES,
            )

            # 5-State Confirmation Evaluation
            confirm_res = ConfirmationEngine.evaluate(
                probe.category,
                verdict,
                raw_evidence=probe_result.raw,
                canary=probe.canary,
            )
            confirm_node = self.evidence_graph.add_node(
                NodeType.CONFIRMATION,
                payload=confirm_res.model_dump(mode="json"),
                parent_ids=[judge_node.id],
                edge_type=EdgeType.CONFIRMS if confirm_res.status.value == "confirmed" else EdgeType.DISPROVES,
            )

            # Attach confirmation and evidence lineage to Finding
            finding = probe_result.to_finding(verdict, severity, self.target_fp)
            finding.raw["confirmation"] = confirm_res.model_dump(mode="json")
            finding.raw["evidence_node_id"] = confirm_node.id
            finding.raw["lineage_sha256"] = confirm_node.sha256
            findings.append(finding)

            # Record replay event
            prompt_hash = hashlib.sha256((effective_prompt or probe.prompt).encode("utf-8")).hexdigest()
            verdict_dict: dict[str, Any] = {
                "label": verdict.label,
                "success": verdict.success,
                "confidence": verdict.confidence,
                "reason": verdict.reason,
                "source": verdict.source,
            }
            self.recorder.record_event(
                ReplayEvent(
                    step_id=step.step_id,
                    probe_id=step.probe_id,
                    prompt_sha256=prompt_hash,
                    response_text=response,
                    error_class=observation.error_class,
                    usage=actual_usage,
                    verdict=verdict_dict,
                )
            )

            # Revise plan adaptively
            if self.options.adaptive or self.options.planner in ("heuristic", "adaptive", "ev_adaptive"):
                revisions = self.planner.revise(self.state, observation, self.probes)
                if hasattr(self.planner, "generated_probes"):
                    planner_generated = getattr(self.planner, "generated_probes", {})
                    self.probe_map.update(planner_generated)
                if revisions:
                    self.state.steps.extend(revisions)
                    log.info(
                        "step %s resulted in %d new adaptive steps",
                        step.step_id,
                        len(revisions),
                    )

        self.state.usage = self.ledger.usage
        manifest = self.recorder.build_manifest(
            final_summary={
                "probes_executed": len(self.state.observations),
                "total_steps": len(self.state.steps),
                "stop_reason": self.state.stop_reason.model_dump() if self.state.stop_reason else None,
                "evidence_nodes_count": len(self.evidence_graph.nodes),
                "target_profile": self.profile.model_dump(mode="json"),
            }
        )
        return findings, self.state, manifest


__all__ = ["AdaptiveEngine"]
