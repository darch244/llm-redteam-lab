"""Autonomous AI red teaming campaign management and differential evaluation."""

from __future__ import annotations

from rtl.campaign.differential import compute_differential_analysis
from rtl.campaign.manager import CampaignManager
from rtl.campaign.models import (
    AsymmetricFinding,
    CampaignConfig,
    CampaignResult,
    DifferentialReport,
    TargetEvaluationResult,
)

__all__ = [
    "AsymmetricFinding",
    "CampaignConfig",
    "CampaignResult",
    "CampaignManager",
    "DifferentialReport",
    "TargetEvaluationResult",
    "compute_differential_analysis",
]
