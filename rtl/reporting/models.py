"""Report data models.

:class:`ProbeResult` is the runtime record of one probe/scenario execution
against a target; :class:`Finding` is its report-ready projection;
:class:`ScanResult` wraps everything a scan produced together with summary
aggregation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from rtl.attacks.model import AttackPrompt
from rtl.evaluation.judge import JudgeVerdict
from rtl.evaluation.severity import SeverityLevel, SeverityResult


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ProbeResult(BaseModel):
    """Raw outcome of one probe or scenario step."""

    probe: AttackPrompt
    response: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    elapsed_seconds: float = 0.0
    skipped: bool = False
    timestamp: datetime = Field(default_factory=_utcnow)

    def to_finding(
        self,
        verdict: JudgeVerdict,
        severity: SeverityResult,
        target: dict[str, Any],
        scenario: str | None = None,
    ) -> Finding:
        """Project a probe execution into a report-ready :class:`Finding`."""
        return Finding(
            attack_id=self.probe.attack_id,
            name=self.probe.name,
            category=self.probe.category,
            technique=self.probe.technique,
            prompt=self.probe.prompt,
            response=self.response,
            atlas_ids=[self.probe.atlas_id],
            verdict_label=verdict.label,
            success=verdict.success,
            confidence=verdict.confidence,
            judge_source=verdict.source,
            severity=severity.level,
            severity_score=severity.score,
            blocked=severity.blocked,
            rationale=severity.rationale,
            scenario=scenario,
            target=target,
            raw=self.raw,
            skipped=self.skipped,
            error=self.error,
            repro_steps=_repro_steps(self.probe, self.response),
            timestamp=self.timestamp,
        )


def _repro_steps(probe: AttackPrompt, response: str) -> list[str]:
    return [
        f"1. Start a fresh chat/session with the target model ({probe.attack_id}).",
        "2. Send the following prompt exactly:",
        f"   {probe.prompt}",
        "3. Observe whether the response exhibits the attack's expected effect.",
        f"4. (Recorded response) {response.strip()[:400] or '<empty>'}",
    ]


class Finding(BaseModel):
    """Report-ready record of one attack result."""

    attack_id: str
    name: str
    category: str
    technique: str
    prompt: str
    response: str
    atlas_ids: list[str] = Field(default_factory=list)
    verdict_label: str
    success: bool
    confidence: float = Field(ge=0.0, le=1.0)
    judge_source: str = "heuristic"
    severity: SeverityLevel
    severity_score: int = Field(ge=0, le=4)
    blocked: bool = False
    rationale: list[str] = Field(default_factory=list)
    scenario: str | None = None
    target: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    repro_steps: list[str] = Field(default_factory=list)
    remediation: str = ""
    skipped: bool = False
    error: str | None = None
    timestamp: datetime = Field(default_factory=_utcnow)

    @field_validator("verdict_label")
    @classmethod
    def _known_verdict(cls, value: str) -> str:
        if value not in {"success", "refused", "ambiguous"}:
            raise ValueError(f"unknown verdict {value!r}")
        return value


class ReportMeta(BaseModel):
    """Scan metadata that goes into every report."""

    tool: str = "llm-redteam-lab"
    version: str = ""
    timestamp: datetime = Field(default_factory=_utcnow)
    target_spec: str = ""
    provider: str = ""
    model: str = ""
    base_url: str | None = None
    suite: str = ""
    suite_description: str = ""
    judge_mode: str = "heuristic"
    duration_seconds: float = 0.0
    notes: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """Aggregate counts across a scan."""

    total: int = 0
    succeeded: int = 0
    refused: int = 0
    ambiguous: int = 0
    blocked: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_atlas: dict[str, int] = Field(default_factory=dict)
    originals: int = 0


class ScanResult(BaseModel):
    """Complete scan artifact (what JSON/HTML/PDF reporters consume)."""

    meta: ReportMeta
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    engine_results: list[dict[str, Any]] = Field(default_factory=list)
    scenario_outcomes: list[dict[str, Any]] = Field(default_factory=list)

    def aggregate(self) -> None:
        """Recompute the summary based on current findings."""
        summary = ScanSummary(
            total=len(self.findings),
            succeeded=sum(1 for f in self.findings if f.success and not f.skipped),
            refused=sum(1 for f in self.findings if f.verdict_label == "refused"),
            ambiguous=sum(1 for f in self.findings if f.verdict_label == "ambiguous"),
            blocked=sum(1 for f in self.findings if f.blocked),
            originals=self._count_originals(),
        )
        for finding in self.findings:
            if finding.skipped:
                continue
            summary.by_severity[finding.severity] = summary.by_severity.get(finding.severity, 0) + 1
            summary.by_category[finding.category] = summary.by_category.get(finding.category, 0) + 1
            for atlas_id in finding.atlas_ids:
                summary.by_atlas[atlas_id] = summary.by_atlas.get(atlas_id, 0) + 1
        # preserve a stable severity ordering in the dicts
        order = ["info", "low", "medium", "high", "critical"]
        summary.by_severity = {k: summary.by_severity.get(k, 0) for k in order}
        self.summary = summary

    @staticmethod
    def _count_originals() -> int:
        from rtl.attacks.loader import load_cache

        return sum(1 for probes in load_cache().values() for probe in probes if probe.source == "original")


__all__ = ["Finding", "ProbeResult", "ReportMeta", "ScanResult", "ScanSummary"]
