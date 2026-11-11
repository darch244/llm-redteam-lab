"""Campaign Manager orchestrating multi-target evaluation and evidence verification."""

from __future__ import annotations

import json
import pathlib
import time
from typing import TYPE_CHECKING, Any

from rtl.campaign.differential import compute_differential_analysis
from rtl.campaign.models import (
    CampaignConfig,
    CampaignResult,
    TargetEvaluationResult,
)
from rtl.config import ScanOptions, Suite, TargetConfig
from rtl.logging import get_logger
from rtl.planning.engine import AdaptiveEngine
from rtl.profiler.detector import ActiveProfiler
from rtl.profiler.models import TargetProfile
from rtl.targets.mock_target import MockTarget

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt
    from rtl.targets.base import Target

log = get_logger("campaign.manager")


class CampaignManager:
    """Enterprise campaign manager coordinating autonomous security evaluations."""

    def __init__(self, config: CampaignConfig, probes: list[AttackPrompt] | None = None) -> None:
        self.config = config
        if probes is None:
            from rtl.attacks.loader import resolve

            self.probes = resolve()
        else:
            self.probes = list(probes)

    async def run_target_campaign(
        self,
        target_info: dict[str, Any],
        target_instance: Target | None = None,
    ) -> TargetEvaluationResult:
        """Run an autonomous evaluation campaign against a single target."""
        start_time = time.time()
        tid = str(target_info.get("target_id") or target_info.get("name") or "target")
        provider = str(target_info.get("provider") or "mock")
        model = str(target_info.get("model") or "mock-model")

        # 1. Instantiate or reuse target
        target = target_instance or MockTarget(model=model)

        # 2. Pre-campaign Active Profiling
        profile: TargetProfile
        if self.config.active_profiling:
            profile = await ActiveProfiler.profile_target(target, target_id=tid)
        else:
            profile = TargetProfile(target_id=tid, provider=provider, model=model)

        # 3. Configure AdaptiveEngine with EV Planner
        options = ScanOptions(
            suite=Suite(name="campaign"),
            planner=self.config.planner,  # type: ignore[arg-type]
            budget=self.config.budget,
            seed=self.config.seed,
            target=TargetConfig(kind=provider, model=model),  # type: ignore[arg-type]
        )
        engine = AdaptiveEngine(
            options=options,
            target=target,
            probes=self.probes,
            target_profile=profile,
        )

        # 4. Execute Campaign
        findings, state, manifest = await engine.run()
        elapsed = time.time() - start_time

        # 5. Verify Evidence Graph Integrity
        valid_integrity, integrity_msg = engine.evidence_graph.verify_integrity()

        # 6. Aggregate Confirmation Counts
        confirmed_count = 0
        corroborated_count = 0
        suspicious_count = 0
        disproven_count = 0

        for f in findings:
            c_status = f.raw.get("confirmation", {}).get("status")
            if c_status == "confirmed":
                confirmed_count += 1
            elif c_status == "corroborated":
                corroborated_count += 1
            elif c_status == "suspicious":
                suspicious_count += 1
            else:
                disproven_count += 1

        return TargetEvaluationResult(
            target_id=tid,
            provider=provider,
            model=model,
            profile=engine.profile,
            total_probes_run=len(state.observations),
            findings_count=len(findings),
            confirmed_findings_count=confirmed_count,
            corroborated_findings_count=corroborated_count,
            suspicious_findings_count=suspicious_count,
            disproven_findings_count=disproven_count,
            findings=findings,
            evidence_graph=engine.evidence_graph,
            evidence_graph_verified=valid_integrity,
            evidence_graph_integrity_msg=integrity_msg,
            elapsed_seconds=elapsed,
            budget_usage=state.usage.model_dump(),
        )

    def save_checkpoint(
        self,
        path: pathlib.Path | str,
        completed_results: dict[str, TargetEvaluationResult],
    ) -> None:
        """Save campaign progress checkpoint for resumability."""
        p = pathlib.Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_data = {
            "campaign_id": self.config.campaign_id,
            "config": self.config.model_dump(mode="json"),
            "completed_targets": list(completed_results.keys()),
            "target_results": {k: v.model_dump(mode="json") for k, v in completed_results.items()},
        }
        with open(p, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2)

    @classmethod
    def load_checkpoint(cls, path: pathlib.Path | str) -> tuple[CampaignConfig, dict[str, TargetEvaluationResult]]:
        """Load an in-progress campaign checkpoint."""
        p = pathlib.Path(path)
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        cfg = CampaignConfig.model_validate(data["config"])
        results = {k: TargetEvaluationResult.model_validate(v) for k, v in data.get("target_results", {}).items()}
        return cfg, results

    async def execute(
        self,
        target_instances: dict[str, Target] | None = None,
        checkpoint_path: pathlib.Path | str | None = None,
        resume_results: dict[str, TargetEvaluationResult] | None = None,
    ) -> CampaignResult:
        """Execute campaign across all configured targets and generate differential analysis."""
        instances = target_instances or {}
        results: dict[str, TargetEvaluationResult] = dict(resume_results or {})

        for t_info in self.config.targets:
            tid = str(t_info.get("target_id") or t_info.get("name") or "target")
            if tid in results:
                log.info("Target '%s' already evaluated in checkpoint; skipping.", tid)
                continue

            log.info("Starting campaign evaluation against target '%s'...", tid)
            t_instance = instances.get(tid)
            res = await self.run_target_campaign(t_info, target_instance=t_instance)
            results[tid] = res

            if checkpoint_path:
                self.save_checkpoint(checkpoint_path, results)

        # Differential analysis if multiple targets were evaluated
        differential = None
        if len(results) >= 2:
            differential = compute_differential_analysis(results)

        all_valid = all(r.evidence_graph_verified for r in results.values())
        summary = (
            f"Campaign '{self.config.campaign_id}' completed across {len(results)} targets. "
            f"Evidence cryptographic integrity: {'VERIFIED' if all_valid else 'TAMPERED'}."
        )

        return CampaignResult(
            campaign_id=self.config.campaign_id,
            target_results=results,
            differential=differential,
            all_evidence_valid=all_valid,
            summary=summary,
        )


__all__ = ["CampaignManager"]
