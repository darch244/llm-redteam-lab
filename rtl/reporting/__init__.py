"""Reporting layer — models, JSON/HTML/PDF reporters."""

from __future__ import annotations

from rtl.reporting.html_reporter import render_html
from rtl.reporting.json_reporter import load_json, write_json
from rtl.reporting.markdown_reporter import render_markdown
from rtl.reporting.models import Finding, ProbeResult, ReportMeta, ScanResult, ScanSummary
from rtl.reporting.sarif_reporter import render_sarif

__all__ = [
    "Finding",
    "ProbeResult",
    "ReportMeta",
    "ScanResult",
    "ScanSummary",
    "load_json",
    "render_html",
    "render_markdown",
    "render_sarif",
    "write_json",
]
