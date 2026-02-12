"""HTML report generator — a single self-contained styled page.

Rendered from ``templates/report.html`` via Jinja2. Includes an executive
summary, per-attack result cards with severity badges, an ATLAS crosswalk,
a severity distribution chart (Chart.js from CDN) and full reproduction
steps per finding.
"""

from __future__ import annotations

import pathlib

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from rtl.evaluation.atlas import ATLAS_MAP
from rtl.reporting.models import ScanResult
from rtl.utils.files import ensure_dir
from rtl.utils.secrets import scrub

_TEMPLATE_DIR = pathlib.Path(__file__).resolve().parent / "templates"


def _build_context(result: ScanResult) -> dict[str, object]:
    findings = []
    for finding in result.findings:
        item = finding.model_dump(mode="json")
        item["response_excerpt"] = scrub(finding.response)[:800]
        item["prompt_excerpt"] = scrub(finding.prompt)[:500]
        item["atlas_names"] = [ATLAS_MAP.get(tech, {}).get("name", tech) for tech in finding.atlas_ids]
        findings.append(item)

    severity_order = ["critical", "high", "medium", "low", "info"]
    by_severity = result.summary.by_severity or {}
    distribution = [{"level": level, "count": by_severity.get(level, 0)} for level in severity_order]

    atlas_crosswalk = [
        {
            "id": tech_id,
            "name": ATLAS_MAP.get(tech_id, {}).get("name", tech_id),
            "count": result.summary.by_atlas.get(tech_id, 0),
            "url": ATLAS_MAP.get(tech_id, {}).get("url", "#"),
        }
        for tech_id in sorted(result.summary.by_atlas, key=lambda i: -result.summary.by_atlas[i])
    ]

    return {
        "meta": result.meta.model_dump(mode="json"),
        "summary": result.summary.model_dump(mode="json"),
        "findings": findings,
        "distribution": distribution,
        "atlas_crosswalk": atlas_crosswalk,
        "engine_results": result.engine_results,
    }


def render_html(
    result: ScanResult,
    output_path: str | pathlib.Path,
    *,
    inline: bool = False,
) -> str:
    """Render the scan to an HTML file (or return the HTML string).

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
    html = template.render(**_build_context(result))
    if inline:
        return html
    dest = ensure_dir(pathlib.Path(output_path).parent) / pathlib.Path(output_path).name
    dest.write_text(html, encoding="utf-8")
    return str(dest)


__all__ = ["render_html"]
