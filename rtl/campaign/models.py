"""Data models for enterprise red teaming campaigns and differential evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from rtl.config import BudgetLimits
from rtl.core.evidence_graph import EvidenceGraph
from rtl.profiler.models import TargetProfile
from rtl.reporting.models import Finding


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TargetEvaluationResult(BaseModel):
    """Consolidated outcome of an attack campaign against one AI target."""

    target_id: str
    provider: str
    model: str
    profile: TargetProfile
    total_probes_run: int
    findings_count: int
    confirmed_findings_count: int
    corroborated_findings_count: int
    suspicious_findings_count: int
    disproven_findings_count: int
    findings: list[Finding] = Field(default_factory=list)
    evidence_graph: EvidenceGraph
    evidence_graph_verified: bool
    evidence_graph_integrity_msg: str
    elapsed_seconds: float
    budget_usage: dict[str, Any] = Field(default_factory=dict)


class AsymmetricFinding(BaseModel):
    """An attack probe whose security outcome diverged between targets."""

    probe_id: str
    category: str
    technique: str
    target_outcomes: dict[str, str]  # target_id -> "confirmed", "refused", etc.
    divergence_type: str  # "vulnerable_vs_defended", "severity_difference"
    impact_summary: str


class DifferentialReport(BaseModel):
    """Comparative analysis across two or more evaluated AI systems."""

    target_ids: list[str]
    divergence_count: int
    divergence_ratio: float  # diverged / total_evaluated
    asymmetric_findings: list[AsymmetricFinding] = Field(default_factory=list)
    relative_ranking: list[dict[str, Any]] = Field(default_factory=list)
    summary: str


class CampaignConfig(BaseModel):
    """Configuration for an autonomous red teaming campaign.

    Note on Budget Semantics:
        The ``budget`` limits (e.g. ``max_probes``, ``max_turns``, ``max_seconds``)
        represent the allocation per individual target in the campaign, ensuring
        equitable evaluation depth across all targets.
    """

    campaign_id: str
    targets: list[dict[str, Any]]  # target configurations
    planner: str = "ev_adaptive"
    budget: BudgetLimits = Field(
        default_factory=BudgetLimits,
        description="Per-target resource execution budget (each target receives this allocation)",
    )
    active_profiling: bool = True
    output_dir: str = "reports/campaigns"
    seed: int = 42


class CampaignResult(BaseModel):
    """Complete campaign delivery package."""

    campaign_id: str
    timestamp: datetime = Field(default_factory=_utcnow)
    target_results: dict[str, TargetEvaluationResult] = Field(default_factory=dict)
    differential: DifferentialReport | None = None
    all_evidence_valid: bool
    summary: str


__all__ = [
    "AsymmetricFinding",
    "CampaignConfig",
    "CampaignResult",
    "DifferentialReport",
    "TargetEvaluationResult",
]
