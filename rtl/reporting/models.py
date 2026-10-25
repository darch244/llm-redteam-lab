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
    effective_prompt: str | None = None
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
            effective_prompt=self.effective_prompt,
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
            repro_steps=_repro_steps(self.probe, self.response, self.effective_prompt),
            timestamp=self.timestamp,
        )


def _repro_steps(probe: AttackPrompt, response: str, effective_prompt: str | None = None) -> list[str]:
    """Build reproduction steps that describe what the target *actually received*.

    When the runner truncates a prompt to ``max_prompt_len`` the probe object
    still carries the full library prompt, so ``effective_prompt`` is threaded
    through to keep the reproduction data faithful. The original prompt is only
    mentioned as a note when truncation changed what was sent.
    """
    sent = effective_prompt if effective_prompt is not None else probe.prompt
    steps = [
        f"1. Start a fresh chat/session with the target model ({probe.attack_id}).",
        "2. Send the following prompt exactly:",
        f"   {sent}",
    ]
    if effective_prompt is not None and effective_prompt != probe.prompt:
        steps.insert(
            2,
            f"   (Note: the library prompt was {len(probe.prompt)} chars and was truncated to "
            f"{len(effective_prompt)} for this scan; the text below is what the target received.)",
        )
    steps.append("3. Observe whether the response exhibits the attack's expected effect.")
    steps.append(f"4. (Recorded response) {response.strip()[:400] or '<empty>'}")
    return steps


class Finding(BaseModel):
    """Report-ready record of one attack result."""

    attack_id: str
    name: str
    category: str
    technique: str
    prompt: str
    effective_prompt: str | None = None
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
    """Aggregate counts across a scan.

    ``total`` and the probe verdict tallies count only single-shot probes; the
    ``scenarios_*`` fields account for the multi-step scenario outcomes
    separately so a successful scenario (e.g. a CRITICAL RAG-poisoning run) is
    never silently missing from the summary. ``by_severity``/``by_category``/
    ``by_atlas`` cover probes only; reporters merge scenario severities into the
    displayed distribution.
    """

    total: int = 0
    succeeded: int = 0
    refused: int = 0
    ambiguous: int = 0
    blocked: int = 0
    errors: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_atlas: dict[str, int] = Field(default_factory=dict)
    originals: int = 0
    scenarios_total: int = 0
    scenarios_succeeded: int = 0
    scenarios_errors: int = 0
    scenarios_by_severity: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Complete scan artifact (what JSON/HTML/PDF reporters consume)."""

    meta: ReportMeta
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    engine_results: list[dict[str, Any]] = Field(default_factory=list)
    scenario_outcomes: list[dict[str, Any]] = Field(default_factory=list)

    def aggregate(self) -> None:
        """Recompute the summary based on current findings.

        Execution errors (``skipped`` findings carrying an ``error``) are counted
        separately and excluded from every security-outcome tally, so a failed
        probe is never misreported as a success, refusal or guardrail.
        """
        summary = ScanSummary(
            total=len(self.findings),
            succeeded=sum(1 for f in self.findings if f.success and not f.skipped),
            refused=sum(1 for f in self.findings if f.verdict_label == "refused" and not f.skipped),
            ambiguous=sum(1 for f in self.findings if f.verdict_label == "ambiguous" and not f.skipped),
            blocked=sum(1 for f in self.findings if f.blocked and not f.skipped),
            errors=sum(1 for f in self.findings if f.skipped and f.error),
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

        # Scenario outcomes are aggregated separately. A judged scenario counts
        # toward scenarios_succeeded and its severity distribution; an errored
        # or skipped scenario is an explicit error; an unsupported scenario is
        # counted in the total but is neither a success nor an error.
        scenario_sev: dict[str, int] = {}
        for outcome in self.scenario_outcomes:
            summary.scenarios_total += 1
            status = outcome.get("status")
            if status in ("error", "skipped"):
                summary.scenarios_errors += 1
                continue
            if status == "unsupported":
                continue
            if outcome.get("success"):
                summary.scenarios_succeeded += 1
            sev = outcome.get("severity")
            if isinstance(sev, str) and sev:
                scenario_sev[sev] = scenario_sev.get(sev, 0) + 1
        summary.scenarios_by_severity = {k: scenario_sev.get(k, 0) for k in order}
        self.summary = summary

    @staticmethod
    def _count_originals() -> int:
        from rtl.attacks.loader import load_cache

        return sum(1 for probes in load_cache().values() for probe in probes if probe.source == "original")


__all__ = ["Finding", "ProbeResult", "ReportMeta", "ScanResult", "ScanSummary"]
