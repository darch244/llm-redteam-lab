"""Scan comparison and security regression diffing engine."""

from __future__ import annotations

import pathlib
from typing import Any

from rtl.reporting.models import ScanResult
from rtl.utils.files import atomic_write_text


def compare_scans(
    baseline: ScanResult,
    candidate: ScanResult,
) -> dict[str, Any]:
    """Compare two scan results and identify fixed issues, regressions, and delta metrics."""
    baseline_map = {f.attack_id: f for f in baseline.findings if not f.skipped}
    candidate_map = {f.attack_id: f for f in candidate.findings if not f.skipped}

    base_target = baseline.meta.target_spec or f"{baseline.meta.provider}:{baseline.meta.model}"
    cand_target = candidate.meta.target_spec or f"{candidate.meta.provider}:{candidate.meta.model}"

    # Target identity check
    is_same_target = (
        baseline.meta.provider == candidate.meta.provider and baseline.meta.model == candidate.meta.model
    ) or (bool(baseline.meta.target_spec) and baseline.meta.target_spec == candidate.meta.target_spec)
    is_same_suite = (
        (baseline.meta.suite == candidate.meta.suite) if (baseline.meta.suite and candidate.meta.suite) else True
    )
    is_comparable = is_same_target

    all_ids = sorted(set(baseline_map) | set(candidate_map))

    fixed: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    persisting: list[dict[str, Any]] = []
    defended: list[dict[str, Any]] = []

    for attack_id in all_ids:
        base_f = baseline_map.get(attack_id)
        cand_f = candidate_map.get(attack_id)

        if base_f is None and cand_f is not None:
            if cand_f.success:
                detail_msg = (
                    f"New probe succeeded in candidate (verdict {cand_f.verdict_label})"
                    if is_comparable
                    else f"Candidate-only probe succeeded on {cand_target} (verdict {cand_f.verdict_label})"
                )
                regressions.append(
                    {
                        "attack_id": attack_id,
                        "name": cand_f.name,
                        "category": cand_f.category,
                        "severity": cand_f.severity,
                        "detail": detail_msg,
                    }
                )
            continue

        if cand_f is None and base_f is not None:
            continue

        assert base_f is not None and cand_f is not None

        if base_f.success and not cand_f.success:
            detail_fixed = (
                f"Fixed: was {base_f.verdict_label} ({base_f.severity}) -> now {cand_f.verdict_label}"
                if is_comparable
                else (
                    f"Baseline ({base_target}) was {base_f.verdict_label} -> "
                    f"candidate ({cand_target}) defended ({cand_f.verdict_label})"
                )
            )
            fixed.append(
                {
                    "attack_id": attack_id,
                    "name": cand_f.name,
                    "category": cand_f.category,
                    "severity": base_f.severity,
                    "detail": detail_fixed,
                }
            )
        elif not base_f.success and cand_f.success:
            detail_reg = (
                f"Regression: was {base_f.verdict_label} -> now {cand_f.verdict_label} ({cand_f.severity})"
                if is_comparable
                else (
                    f"Divergence: baseline ({base_target}) was {base_f.verdict_label} -> "
                    f"candidate ({cand_target}) was {cand_f.verdict_label} ({cand_f.severity})"
                )
            )
            regressions.append(
                {
                    "attack_id": attack_id,
                    "name": cand_f.name,
                    "category": cand_f.category,
                    "severity": cand_f.severity,
                    "detail": detail_reg,
                }
            )
        elif base_f.success and cand_f.success:
            persisting.append(
                {
                    "attack_id": attack_id,
                    "name": cand_f.name,
                    "category": cand_f.category,
                    "severity": cand_f.severity,
                    "detail": "Vulnerability persists in both scans",
                }
            )
        else:
            defended.append(
                {
                    "attack_id": attack_id,
                    "name": cand_f.name,
                    "category": cand_f.category,
                    "detail": "Defended in both scans",
                }
            )

    success_delta = candidate.summary.succeeded - baseline.summary.succeeded

    reg_label = "Regressions (New Failures)" if is_comparable else "Divergent Findings (Candidate Succeeded)"

    diff_summary = {
        "baseline_target": base_target,
        "candidate_target": cand_target,
        "is_same_target": is_same_target,
        "is_same_suite": is_same_suite,
        "is_comparable": is_comparable,
        "comparison_type": "security_regression" if is_comparable else "cross_target",
        "regression_label": reg_label,
        "baseline_succeeded": baseline.summary.succeeded,
        "candidate_succeeded": candidate.summary.succeeded,
        "success_delta": success_delta,
        "fixed_count": len(fixed),
        "regression_count": len(regressions),
        "persisting_count": len(persisting),
        "defended_count": len(defended),
        "fixed": fixed,
        "regressions": regressions,
        "persisting": persisting,
    }
    return diff_summary


def render_diff_markdown(diff: dict[str, Any], dest: str | pathlib.Path) -> pathlib.Path:
    """Render a GitHub-Flavored Markdown report comparing two scans."""
    target_path = pathlib.Path(dest)
    is_comparable = diff.get("is_comparable", True)
    title = (
        "# ⚖️ LLM Red Team Lab — Security Regression Diff\n"
        if is_comparable
        else "# ⚖️ LLM Red Team Lab — Cross-Target Differential Comparison\n"
    )
    lines: list[str] = [
        title,
        f"**Baseline Target:** `{diff['baseline_target']}` | **Candidate Target:** `{diff['candidate_target']}`\n",
    ]

    if not is_comparable:
        lines.extend(
            [
                "> [!WARNING]",
                (
                    f"> **Cross-Target Comparison Notice:** Baseline target (`{diff['baseline_target']}`) "
                    f"and candidate target (`{diff['candidate_target']}`) differ."
                ),
                (
                    "> Divergent findings represent cross-model architectural variance rather than "
                    "security regressions within a single system."
                ),
                "",
            ]
        )

    reg_count_badge = f"**{diff['regression_count']}** {'🔴' if is_comparable else '🟡'}"
    label = diff.get("regression_label", "Regressions (New Failures)")
    lines.extend(
        [
            "## Summary Delta\n",
            "| Metric | Baseline | Candidate | Delta |",
            "| --- | ---: | ---: | ---: |",
            (
                f"| **Vulnerabilities Landed** | {diff['baseline_succeeded']} | "
                f"{diff['candidate_succeeded']} | {diff['success_delta']:+d} |"
            ),
            f"| **Fixed Vulnerabilities** | — | — | **{diff['fixed_count']}** 🟢 |",
            f"| **{label}** | — | — | {reg_count_badge} |",
            f"| **Persisting Vulnerabilities** | — | — | {diff['persisting_count']} 🟡 |",
            f"| **Consistently Defended** | — | — | {diff['defended_count']} 🛡️ |",
            "",
        ]
    )

    if diff["regressions"]:
        section_hdr = (
            "## 🚨 Regressions (Action Required)\n"
            if is_comparable
            else "## ⚠️ Divergent Vulnerabilities (Candidate Succeeded)\n"
        )
        lines.append(section_hdr)
        lines.append("| Attack ID | Name | Category | Severity | Detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for r in diff["regressions"]:
            lines.append(
                f"| `{r['attack_id']}` | {r['name']} | {r['category']} | `{r['severity'].upper()}` | {r['detail']} |"
            )
        lines.append("")

    if diff["fixed"]:
        section_fixed = (
            "## ✅ Resolved Vulnerabilities\n"
            if is_comparable
            else "## 🛡️ Divergent Defenses (Baseline Only Defended)\n"
        )
        lines.append(section_fixed)
        lines.append("| Attack ID | Name | Category | Prior Severity | Detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in diff["fixed"]:
            lines.append(
                f"| `{f['attack_id']}` | {f['name']} | {f['category']} | `{f['severity'].upper()}` | {f['detail']} |"
            )
        lines.append("")

    content = "\n".join(lines) + "\n"
    atomic_write_text(target_path, content)
    return target_path


__all__ = ["compare_scans", "render_diff_markdown"]
