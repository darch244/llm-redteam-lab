"""LLM Red Team Lab — an adversarial testing framework for LLM applications.

Prompt injection, jailbreaks, system-prompt extraction and AI-agent attack
simulation, with MITRE ATLAS mapping and automated JSON/HTML reporting.

This project is intended for authorized security testing only. See
``DISCLAIMER.md`` and ``docs/ethics.md`` before use.
"""

from __future__ import annotations

from rtl._version import __version__
from rtl.config import ScanOptions, Suite, TargetConfig
from rtl.reporting.models import Finding, ProbeResult, ScanResult

__all__ = [
    "__version__",
    "Finding",
    "ProbeResult",
    "ScanOptions",
    "ScanResult",
    "Suite",
    "TargetConfig",
]
