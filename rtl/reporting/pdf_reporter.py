"""Optional PDF exporter (reportlab).

Kept optional so the core works without heavy native dependencies. Swift
comeback if reportlab is available: ``pip install llm-redteam-lab[pdf]``.

Every value interpolated into the document is scrubbed with the same policy
as the HTML report and XML-escaped before it reaches reportlab's paragraph
parser. This covers metadata, finding names/IDs, prompts, responses, errors
and scenario outcomes.
"""

from __future__ import annotations

import pathlib
from typing import Any
from xml.sax.saxutils import escape

from rtl.logging import get_logger
from rtl.reporting.models import ScanResult, scenario_status_counts
from rtl.utils.secrets import scrub

log = get_logger("reporting")

try:  # pragma: no cover - exercised only in optional path
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except ImportError:  # pragma: no cover
    _REPORTLAB_AVAILABLE = False
else:  # pragma: no cover
    _REPORTLAB_AVAILABLE = True


def _pdf_text(value: object, limit: int | None = None) -> str:
    """Scrub a rendered value, truncate it, and escape reportlab markup."""
    text = scrub(str(value))
    if limit is not None:
        text = text[:limit]
    return escape(text)


def _scenario_status(item: dict[str, Any]) -> str:
    """Displayed status: explicit lifecycle status first, then outcome."""
    return str(item.get("status") or item.get("outcome") or "unknown")


def render_pdf(result: ScanResult, output_path: str | pathlib.Path) -> pathlib.Path:
    """Write an A4 PDF summary of the scan result."""
    if not _REPORTLAB_AVAILABLE:
        raise RuntimeError("PDF export requires reportlab: pip install llm-redteam-lab[pdf]")

    dest = pathlib.Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11,
        )
    )

    story: list[object] = []
    story.append(Paragraph("LLM Red Team Lab — Scan Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))
    meta = result.meta
    story.append(
        Paragraph(
            f"Target: <b>{_pdf_text(meta.provider)}:{_pdf_text(meta.model)}</b><br/>"
            f"Suite: <b>{_pdf_text(meta.suite)}</b>"
            + (f" — {_pdf_text(meta.suite_description)}" if meta.suite_description else "")
            + f"<br/>Run at: {meta.timestamp:%Y-%m-%d %H:%M:%S} UTC<br/>"
            f"Judge mode: {_pdf_text(meta.judge_mode)}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    rows: list[list[str]] = [["Severity", "Count"]]
    for level in ("critical", "high", "medium", "low", "info"):
        rows.append([level, str(result.summary.by_severity.get(level, 0))])
    table = Table(rows, colWidths=[1.6 * inch, 1.0 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    for finding in result.findings:
        if finding.skipped:
            continue
        title = f"{finding.severity.upper()} — {finding.name} ({finding.attack_id})"
        story.append(Paragraph(_pdf_text(title), styles["Heading3"]))
        story.append(
            Paragraph(
                _pdf_text(
                    f"Verdict: {finding.verdict_label} / success={finding.success} "
                    f"/ confidence={finding.confidence:.2f}"
                ),
                styles["Small"],
            )
        )
        if finding.error:
            story.append(Paragraph(_pdf_text(f"Error: {finding.error}"), styles["Small"]))
        story.append(Paragraph(_pdf_text(finding.prompt, 600), styles["Small"]))
        story.append(Paragraph(_pdf_text(finding.response, 600), styles["Small"]))
        story.append(Spacer(1, 0.12 * inch))

    if result.scenario_outcomes:
        counts = scenario_status_counts(result.scenario_outcomes)
        story.append(Paragraph("Scenarios", styles["Heading2"]))
        story.append(
            Paragraph(
                _pdf_text(
                    f"{counts['total']} scenario results — "
                    f"{counts['confirmed']} confirmed, "
                    f"{counts['suspected']} suspected, "
                    f"{counts['failed']} failed, "
                    f"{counts['inconclusive']} inconclusive, "
                    f"{counts['error']} errors, "
                    f"{counts['skipped']} skipped, "
                    f"{counts['unsupported']} unsupported"
                ),
                styles["Small"],
            )
        )
        story.append(Spacer(1, 0.1 * inch))
        for item in result.scenario_outcomes:
            status = _scenario_status(item)
            probe_id = item.get("probe_id") or "—"
            name = item.get("name") or ""
            title = f"{status.upper()} — {name} ({probe_id})" if name else f"{status.upper()} — {probe_id}"
            story.append(Paragraph(_pdf_text(title), styles["Heading3"]))
            details = [f"scenario={item.get('scenario', '—')}", f"status={status}"]
            if item.get("outcome"):
                details.append(f"outcome={item['outcome']}")
            if item.get("severity"):
                details.append(f"severity={item['severity']}")
            story.append(Paragraph(_pdf_text(" · ".join(details)), styles["Small"]))
            if item.get("error"):
                story.append(Paragraph(_pdf_text(f"Error: {item['error']}"), styles["Small"]))
            if item.get("response"):
                story.append(Paragraph(_pdf_text(item["response"], 600), styles["Small"]))
            story.append(Spacer(1, 0.12 * inch))

    doc = SimpleDocTemplate(str(dest), pagesize=A4)
    doc.build(story)
    log.info("PDF report written to %s", dest)
    return dest


__all__ = ["render_pdf"]
