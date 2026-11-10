"""Differential security evaluation comparing attack outcomes across targets."""

from __future__ import annotations

from typing import Any

from rtl.campaign.models import (
    AsymmetricFinding,
    DifferentialReport,
    TargetEvaluationResult,
)


def compute_differential_analysis(
    target_results: dict[str, TargetEvaluationResult],
) -> DifferentialReport:
    """Compare evaluation outcomes across targets to find asymmetric vulnerabilities and divergence."""
    target_ids = list(target_results.keys())
    if len(target_ids) < 2:
        return DifferentialReport(
            target_ids=target_ids,
            divergence_count=0,
            divergence_ratio=0.0,
            summary="Differential analysis requires at least two evaluated targets.",
        )

    # 1. Map probe outcomes per target
    # probe_id -> { target_id -> status }
    probe_outcomes: dict[str, dict[str, str]] = {}
    probe_metadata: dict[str, dict[str, str]] = {}

    for tid, res in target_results.items():
        for f in res.findings:
            pid = f.attack_id
            if pid not in probe_outcomes:
                probe_outcomes[pid] = {}
                probe_metadata[pid] = {
                    "category": f.category,
                    "technique": f.technique,
                }
            # Determine outcome label
            conf_data = f.raw.get("confirmation", {})
            status = conf_data.get("status") or ("confirmed" if f.success else "refused")
            probe_outcomes[pid][tid] = status

    # 2. Identify Asymmetric Vulnerabilities
    asymmetric_findings: list[AsymmetricFinding] = []
    divergent_probes = 0

    for pid, outcomes in probe_outcomes.items():
        # Only evaluate probes attempted on more than one target
        if len(outcomes) < 2:
            continue

        distinct_statuses = set(outcomes.values())
        if len(distinct_statuses) > 1:
            divergent_probes += 1

            # Check if this is a vulnerable vs defended divergence
            has_confirmed = any(s in ("confirmed", "corroborated") for s in outcomes.values())
            has_refused = any(s in ("refused", "disproven") for s in outcomes.values())

            div_type = "vulnerable_vs_defended" if (has_confirmed and has_refused) else "severity_difference"

            details = [f"{t}: {s}" for t, s in outcomes.items()]
            asymmetric_findings.append(
                AsymmetricFinding(
                    probe_id=pid,
                    category=probe_metadata[pid]["category"],
                    technique=probe_metadata[pid]["technique"],
                    target_outcomes=outcomes,
                    divergence_type=div_type,
                    impact_summary=f"Divergence across targets: {', '.join(details)}",
                )
            )

    total_probes_evaluated = len([p for p, o in probe_outcomes.items() if len(o) >= 2])
    ratio = round(divergent_probes / total_probes_evaluated, 3) if total_probes_evaluated > 0 else 0.0

    # 3. Relative Ranking (Sort by confirmed vulnerabilities ascending)
    ranking: list[dict[str, Any]] = []
    for tid, res in target_results.items():
        score = (res.confirmed_findings_count * 3.0) + (res.corroborated_findings_count * 1.5)
        ranking.append(
            {
                "target_id": tid,
                "provider": res.provider,
                "model": res.model,
                "confirmed_compromises": res.confirmed_findings_count,
                "risk_score": score,
            }
        )
    ranking.sort(key=lambda r: float(r["risk_score"]))

    summary = (
        f"Differential evaluation evaluated {len(target_ids)} targets across {total_probes_evaluated} "
        f"common probes. Found {divergent_probes} divergent outcomes (divergence ratio: {ratio:.1%}). "
        f"Top resilient target: '{ranking[0]['target_id']}' with {ranking[0]['confirmed_compromises']} "
        "confirmed compromises."
    )

    return DifferentialReport(
        target_ids=target_ids,
        divergence_count=divergent_probes,
        divergence_ratio=ratio,
        asymmetric_findings=asymmetric_findings,
        relative_ranking=ranking,
        summary=summary,
    )


__all__ = ["compute_differential_analysis"]
