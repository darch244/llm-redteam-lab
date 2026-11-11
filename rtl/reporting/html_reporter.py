"""HTML report generator — a single self-contained styled page.

Rendered from ``templates/report.html`` via Jinja2. Includes an executive
summary, per-attack result cards with severity badges, an ATLAS crosswalk,
an inline severity distribution (pure CSS — no external assets, so the report
renders offline) and full reproduction steps per finding.
"""

from __future__ import annotations

import pathlib
from typing import Any, cast

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from rtl.evaluation.atlas import ATLAS_MAP
from rtl.reporting.models import ScanResult, scenario_status_counts
from rtl.utils.files import ensure_dir
from rtl.utils.secrets import scrub, scrub_dict

_TEMPLATE_DIR = pathlib.Path(__file__).resolve().parent / "templates"


def _redactor(redact: bool) -> Any:
    """Return the scrub function when redaction is on, else an identity map.

    Redaction is the safe default; ``redact=False`` exists only for local
    debugging on synthetic targets and is threaded explicitly from ScanOptions
    so the CLI flag is real rather than cosmetic.
    """
    return scrub if redact else (lambda value: value)


def _build_context(result: ScanResult, *, redact: bool = True) -> dict[str, object]:
    _scrub = _redactor(redact)
    findings = []
    for finding in result.findings:
        raw_item = finding.model_dump(mode="json")
        item = cast(dict[str, Any], scrub_dict(raw_item)) if redact else raw_item
        item["response_excerpt"] = _scrub(finding.response)[:800]
        item["prompt_excerpt"] = _scrub(finding.prompt)[:500]
        item["effective_prompt_excerpt"] = _scrub(finding.effective_prompt)[:500] if finding.effective_prompt else ""
        item["atlas_names"] = [ATLAS_MAP.get(tech, {}).get("name", tech) for tech in item.get("atlas_ids", [])]
        item["is_execution_error"] = finding.is_execution_error
        findings.append(item)

    severity_order = ["critical", "high", "medium", "low", "info"]
    # The severity chart and ATLAS crosswalk cover probe *and* scenario findings,
    # so a CRITICAL scenario success is visible alongside probe findings.
    combined_severity = dict(result.summary.by_severity or {})
    for level, count in (result.summary.scenarios_by_severity or {}).items():
        combined_severity[level] = combined_severity.get(level, 0) + count
    distribution: list[dict[str, int | str]] = [
        {"level": level, "count": combined_severity.get(level, 0)} for level in severity_order
    ]

    combined_atlas = dict(result.summary.by_atlas or {})
    for outcome in result.scenario_outcomes:
        for atlas_id in outcome.get("atlas_ids") or []:
            combined_atlas[atlas_id] = combined_atlas.get(atlas_id, 0) + 1

    max_severity = max((int(row["count"]) for row in distribution), default=0)

    atlas_crosswalk = [
        {
            "id": tech_id,
            "name": ATLAS_MAP.get(tech_id, {}).get("name", tech_id),
            "count": combined_atlas.get(tech_id, 0),
            "url": ATLAS_MAP.get(tech_id, {}).get("url", "#"),
        }
        for tech_id in sorted(combined_atlas, key=lambda i: -combined_atlas[i])
    ]

    meta_dict = scrub_dict(result.meta.model_dump(mode="json")) if redact else result.meta.model_dump(mode="json")
    summary_dict = (
        scrub_dict(result.summary.model_dump(mode="json")) if redact else result.summary.model_dump(mode="json")
    )
    return {
        "meta": meta_dict,
        "summary": summary_dict,
        "findings": findings,
        "scenario_outcomes": [_scenario_row(outcome, redact=redact) for outcome in result.scenario_outcomes],
        "scenario_counts": scenario_status_counts(result.scenario_outcomes),
        "distribution": distribution,
        "max_severity": max_severity,
        "atlas_crosswalk": scrub_dict(atlas_crosswalk) if redact else atlas_crosswalk,
        "engine_results": scrub_dict(result.engine_results) if redact else result.engine_results,
        "adaptive": result.adaptive,
    }


def _scenario_row(outcome: dict[str, Any], *, redact: bool = True) -> dict[str, object]:
    """Normalize a heterogeneous scenario outcome for the template.

    Judged outcomes are :class:`Finding` dumps (carrying ``verdict_label``,
    ``severity`` and a nested ``raw.verdict.reason``); skipped/unsupported/error
    outcomes instead carry a ``status`` and an ``error``. Both shapes are
    flattened to one key set so the template stays free of conditionals on
    missing keys. Evidence is scrubbed before it reaches the page unless
    ``redact`` is false.
    """
    view = cast(dict[str, Any], scrub_dict(outcome)) if redact else dict(outcome)
    _scrub = _redactor(redact)
    raw = view.get("raw")
    reason = ""
    if isinstance(raw, dict):
        verdict = raw.get("verdict")
        if isinstance(verdict, dict):
            reason = str(verdict.get("reason", "") or "")
    response = view.get("response")
    attack_id = view.get("attack_id") or view.get("probe_id")
    status_label = str(view.get("status") or view.get("outcome") or "judged")
    error = view.get("error")
    return {
        "scenario": view.get("scenario") or "—",
        "attack_id": attack_id or "—",
        "probe_label": attack_id or "—",
        "name": view.get("name") or "",
        "status": view.get("status", "judged"),
        "status_label": status_label,
        "outcome": view.get("outcome"),
        "verdict_label": view.get("verdict_label"),
        "severity": view.get("severity"),
        "success": view.get("success"),
        "confidence": view.get("confidence"),
        "judge_source": view.get("judge_source"),
        "error": error,
        "error_excerpt": _scrub(str(error))[:800] if error else "",
        "reason": _scrub(reason)[:300] if reason else "",
        "response_excerpt": _scrub(str(response))[:800] if response else "",
    }


def render_html(
    result: ScanResult,
    output_path: str | pathlib.Path,
    *,
    inline: bool = False,
    redact: bool = True,
) -> str:
    """Render the scan to an HTML file (or return the HTML string).

    Args:
        result: The scan to render.
        output_path: Destination file path.
        inline: When true, return the HTML string instead of writing a file.
        redact: Scrub secrets from evidence before rendering (default true).

    Returns:
        The rendered HTML string when ``inline`` is true; otherwise the
        resolved output path as a string.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        autoescape=True,
    )
    template = env.get_template("report.html")
    html = template.render(**_build_context(result, redact=redact))
    if inline:
        return html
    dest = ensure_dir(pathlib.Path(output_path).parent) / pathlib.Path(output_path).name
    dest.write_text(html, encoding="utf-8")
    return str(dest)


__all__ = ["render_html"]
