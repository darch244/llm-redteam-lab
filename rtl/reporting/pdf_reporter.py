"""Optional PDF exporter (reportlab).

Kept optional so the core works without heavy native dependencies. If
reportlab is available (``pip install llm-redteam-lab[pdf]``), :func:`render_pdf`
writes an A4 summary; otherwise it raises :class:`RuntimeError` with the install
hint. Untrusted evidence is XML-escaped before it reaches reportlab's paragraph
parser so model output cannot inject markup or break the build.
"""

from __future__ import annotations

import pathlib
from xml.sax.saxutils import escape

from rtl.logging import get_logger
from rtl.reporting.models import ScanResult
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
            f"Target: <b>{escape(meta.provider)}:{escape(meta.model)}</b><br/>"
            f"Suite: <b>{escape(meta.suite)}</b><br/>"
            f"Run at: {meta.timestamp:%Y-%m-%d %H:%M:%S} UTC<br/>"
            f"Judge mode: {escape(meta.judge_mode)}",
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
        title = f"{escape(finding.severity.upper())} — {escape(finding.name)} ({escape(finding.attack_id)})"
        story.append(Paragraph(title, styles["Heading3"]))
        story.append(
            Paragraph(
                f"<i>Verdict:</i> {escape(finding.verdict_label)} / success={finding.success} "
                f"/ confidence={finding.confidence:.2f}",
                styles["Small"],
            )
        )
        story.append(Paragraph(escape(scrub(finding.prompt)[:600]), styles["Small"]))
        story.append(Paragraph(escape(scrub(finding.response)[:600]), styles["Small"]))
        story.append(Spacer(1, 0.12 * inch))

    doc = SimpleDocTemplate(str(dest), pagesize=A4)
    doc.build(story)
    log.info("PDF report written to %s", dest)
    return dest


__all__ = ["render_pdf"]
