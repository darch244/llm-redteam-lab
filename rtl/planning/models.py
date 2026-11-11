"""Data models for the adaptive red-teaming planner, budget ledger, and replay.

All models are Pydantic v2 ``BaseModel``s so they serialise into existing
report dictionaries, JSON payloads, and test fixtures without custom encoders.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from rtl.config import BudgetLimits
from rtl.evaluation.judge import JudgeVerdict

SignalKind = Literal[
    "canary_disclosed",
    "concrete_secret",
    "policy_violating_execution",
    "refusal",
    "deflection",
    "blocked_tool_call",
    "proposed_only",
    "textual_mention",
    "unsupported_claim",
    "error",
    "timeout",
    "malformed_response",
    "budget_exhausted",
]

SignalSource = Literal["judge", "runtime", "transport", "planner"]

StopDimension = Literal[
    "max_probes",
    "max_turns",
    "max_seconds",
    "max_prompt_tokens",
    "max_output_tokens",
    "max_cost_usd",
    "max_tool_calls",
    "plan_complete",
    "target_degraded",
    "user_stop",
]


class EvidenceSignal(BaseModel):
    """Normalized evidence token extracted from an observation."""

    kind: SignalKind
    strength: float = Field(default=1.0, ge=0.0, le=1.0)
    source: SignalSource = "judge"
    detail: str = Field(default="", max_length=500)


class BudgetUsage(BaseModel):
    """Resource consumption recorded across one or more execution steps."""

    probes: int = Field(default=0, ge=0)
    turns: int = Field(default=0, ge=0)
    prompt_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    tool_calls: int = Field(default=0, ge=0)
    elapsed_seconds: float = Field(default=0.0, ge=0.0)

    def add(self, other: BudgetUsage) -> BudgetUsage:
        """Return a new BudgetUsage combining self and other."""
        return BudgetUsage(
            probes=self.probes + other.probes,
            turns=self.turns + other.turns,
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cost_usd=round(self.cost_usd + other.cost_usd, 6),
            tool_calls=self.tool_calls + other.tool_calls,
            elapsed_seconds=round(self.elapsed_seconds + other.elapsed_seconds, 3),
        )


class StopReason(BaseModel):
    """The reason an adaptive execution terminated."""

    dimension: StopDimension
    detail: str = ""
    turn: int = Field(default=0, ge=0)


class PlanStep(BaseModel):
    """A scheduled or executed attack step within an adaptive plan."""

    step_id: str
    probe_id: str
    category: str
    technique: str = ""
    rationale: str
    parent_step_id: str | None = None
    expected_evidence: list[str] = Field(default_factory=list)
    est_prompt_tokens: int = Field(default=1, ge=1)
    est_max_output_tokens: int = Field(default=256, ge=1)
    est_cost_usd: float = Field(default=0.0, ge=0.0)


class Observation(BaseModel):
    """Outcome and evidence collected from executing a single PlanStep."""

    step_id: str
    probe_id: str
    category: str
    verdict: JudgeVerdict
    signals: list[EvidenceSignal] = Field(default_factory=list)
    response_excerpt: str = ""
    error_class: str | None = None
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    elapsed_seconds: float = 0.0
    replay_index: int | None = None


class PlanState(BaseModel):
    """Complete mutable working state of an adaptive planning session."""

    plan_id: str
    objective: str = "adversarial_resilience_audit"
    steps: list[PlanStep] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    limits: BudgetLimits = Field(default_factory=BudgetLimits)
    stop_reason: StopReason | None = None


class ReplayEvent(BaseModel):
    """A single deterministic record of target invocation for audit/replay."""

    step_id: str
    probe_id: str
    prompt_sha256: str
    response_text: str
    error_class: str | None = None
    usage: BudgetUsage
    verdict: dict[str, Any]


class ReplayManifest(BaseModel):
    """Self-contained audit manifest for replaying an adaptive scan."""

    schema_version: int = 1
    engine_version: str = "0.1.0"
    planner_name: str
    planner_version: str
    seed: int
    suite_name: str
    suite_hash: str
    probe_catalog_hash: str
    dataset_version: int | None = None
    dataset_hash: str | None = None
    limits: BudgetLimits
    judge_mode: str
    target_fingerprint: dict[str, Any]
    events: list[ReplayEvent] = Field(default_factory=list)
    final_summary: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = True


__all__ = [
    "BudgetLimits",
    "BudgetUsage",
    "EvidenceSignal",
    "Observation",
    "PlanState",
    "PlanStep",
    "ReplayEvent",
    "ReplayManifest",
    "SignalKind",
    "SignalSource",
    "StopDimension",
    "StopReason",
]
