"""Markdown report generator for PR comments, technical briefs, and documentation."""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING

from rtl.evaluation.atlas import ATLAS_MAP
from rtl.utils.files import atomic_write_text
from rtl.utils.secrets import scrub

if TYPE_CHECKING:
    from rtl.reporting.models import ScanResult


def render_markdown(
    result: ScanResult,
    dest: str | pathlib.Path,
    *,
    redact: bool = True,
) -> pathlib.Path:
    """Render a GitHub-Flavored Markdown summary report."""
    target_path = pathlib.Path(dest)
    lines: list[str] = []
    _scrub = scrub if redact else (lambda v: str(v))

    lines.append("# 🛡️ LLM Red Team Lab — Security Assessment Report\n")
    lines.append(
        f"**Target:** `{result.meta.provider}:{result.meta.model}` | "
        f"**Suite:** `{result.meta.suite}` | "
        f"**Timestamp:** `{result.meta.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}` | "
        f"**Duration:** `{result.meta.duration_seconds:.2f}s`\n"
    )

    # Executive Summary Table
    lines.append("## Executive Summary\n")
    lines.append("| Metric | Value | Description |")
    lines.append("| --- | ---: | --- |")
    lines.append(f"| **Total Probes** | {result.summary.total} | Total adversarial probes evaluated |")
    lines.append(f"| **Compromised (Success)** | **{result.summary.succeeded}** | Probes that bypassed guardrails |")
    lines.append(f"| **Refused (Protected)** | {result.summary.refused} | Explicit policy refusals / guardrails |")
    lines.append(f"| **Guarded / Blocked** | {result.summary.blocked} | Simulated tool / runtime calls blocked |")
    lines.append(f"| **Ambiguous / Inconclusive** | {result.summary.ambiguous} | Findings requiring manual review |")
    lines.append(f"| **Scan Errors** | {result.summary.errors} | Target transport or runtime exceptions |")
    lines.append("")

    # Severity Breakdown
    lines.append("## Severity Breakdown\n")
    lines.append("| Severity Level | Findings | Security Impact |")
    lines.append("| --- | ---: | --- |")
    sev_emoji = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "⚪ INFO",
    }
    for level, count in (result.summary.by_severity or {}).items():
        badge = sev_emoji.get(level, level.upper())
        status = "Requires Immediate Action" if level in ("critical", "high") and count > 0 else "Monitored"
        lines.append(f"| {badge} | {count} | {status} |")
    lines.append("")

    # Adaptive Planning Trace (if present)
    if result.adaptive:
        lines.append("## Adaptive Attack Plan Trace\n")
        manifest = result.adaptive.get("manifest", {})
        plan_state = result.adaptive.get("plan_state", {})
        p_name = manifest.get("planner_name", "adaptive")
        p_ver = manifest.get("planner_version", "1.0.0")
        lines.append(f"- **Planner:** `{p_name}` (v{p_ver})")
        lines.append(f"- **Seed:** `{manifest.get('seed', 'default')}`")
        lines.append(f"- **Total Strategy Steps:** `{len(plan_state.get('steps', []))}`")
        stop_reason = plan_state.get("stop_reason")
        if stop_reason:
            lines.append(f"- **Termination:** `{stop_reason.get('dimension')}` ({stop_reason.get('detail')})")
        lines.append("")

        lines.append("| Step | Probe | Category | Rationale | Verdict |")
        lines.append("| --- | --- | --- | --- | --- |")
        for step in plan_state.get("steps", []):
            step_id = step.get("step_id")
            probe_id = step.get("probe_id")
            category = step.get("category")
            rationale = step.get("rationale")

            verdict_str = "—"
            for obs in plan_state.get("observations", []):
                if obs.get("step_id") == step_id:
                    v = obs.get("verdict", {})
                    label = v.get("label", "")
                    sigs = [s.get("kind", "") for s in obs.get("signals", [])]
                    sig_pills = f" (`{', '.join(sigs[:2])}`)" if sigs else ""
                    verdict_str = f"**{label}**{sig_pills}"
                    break
            lines.append(f"| `{step_id}` | `{probe_id}` | {category} | {rationale} | {verdict_str} |")
        lines.append("")

    # Detailed Findings Table
    lines.append("## Key Findings\n")
    if not result.findings:
        lines.append("_No findings recorded for this assessment._\n")
    else:
        lines.append("| ID | Attack Name | Category | ATLAS | Verdict | Severity |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for f in result.findings:
            if f.skipped:
                continue
            atlas_id = f.atlas_ids[0] if f.atlas_ids else "AML.T0051"
            atlas_name = ATLAS_MAP.get(atlas_id, {}).get("name", atlas_id)
            verdict_badge = f"**{f.verdict_label}**" if f.success else f.verdict_label
            atlas_url = ATLAS_MAP.get(atlas_id, {}).get("url", "#")
            lines.append(
                f"| `{f.attack_id}` | {f.name} | {f.category} | "
                f"[{atlas_id}]({atlas_url}) - {atlas_name} | {verdict_badge} | `{f.severity.upper()}` |"
            )
        lines.append("")

    # Scenario Outcomes
    if result.scenario_outcomes:
        lines.append("## Multi-Step Scenario Outcomes\n")
        lines.append("| Scenario | Probe ID | Status | Verdict | Severity | Note |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for s in result.scenario_outcomes:
            sc_name = s.get("scenario", "")
            pr_id = s.get("attack_id", "—")
            status = s.get("status", "ok")
            v_label = s.get("verdict_label", "—")
            sev = s.get("severity", "—")
            raw_reason = s.get("reason") or s.get("error") or ""
            reason = str(raw_reason)
            lines.append(f"| `{sc_name}` | `{pr_id}` | {status} | {v_label} | {sev} | {reason[:120]} |")
        lines.append("")

    # Actionable Remediation Guidance
    lines.append("## Actionable Hardening Recommendations\n")
    lines.append(
        "1. **Strict Context Isolation:** Delimit user-controlled inputs with structured delimiters "
        "(e.g. `<user_input>...</user_input>`)."
    )
    lines.append(
        "2. **Instruction Hierarchy:** Configure system prompts with clear precedence rules "
        "explicitly forbidding override by untrusted inputs."
    )
    lines.append(
        "3. **Runtime Tool Sandboxing:** Require explicit human-in-the-loop confirmation for "
        "sensitive tool invocations (email, database, shell)."
    )
    lines.append(
        "4. **Canary & Secret Scrubbing:** Implement synthetic canaries and secret detection filters "
        "to prevent data leakage in responses.\n"
    )

    lines.append("---\n")
    ver_str = result.meta.version or "0.1.0"
    lines.append(f"_Generated by `llm-redteam-lab` v{ver_str}. Authorized security testing only._")

    content = "\n".join(lines) + "\n"
    atomic_write_text(target_path, _scrub(content))
    return target_path


__all__ = ["render_markdown"]
