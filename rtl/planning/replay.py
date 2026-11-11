"""Deterministic replay engine, recorder, and manifest validation."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

from rtl.logging import get_logger
from rtl.planning.models import ReplayEvent, ReplayManifest
from rtl.targets.base import Target

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt
    from rtl.config import BudgetLimits, Suite

log = get_logger("planning.replay")


def compute_catalog_hash(probes: list[AttackPrompt]) -> str:
    """Compute a reproducible SHA-256 digest over the probe catalog."""
    hasher = hashlib.sha256()
    for probe in sorted(probes, key=lambda p: p.attack_id):
        hasher.update(f"{probe.attack_id}:{probe.prompt}".encode())
    return hasher.hexdigest()


def compute_suite_hash(suite: Suite) -> str:
    """Compute a reproducible SHA-256 digest over the suite definition."""
    data = json.dumps(suite.model_dump(mode="json"), sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class ReplayRecorder:
    """Records dispatch events during a scan to generate an audit manifest."""

    def __init__(
        self,
        planner_name: str,
        planner_version: str,
        seed: int,
        suite: Suite,
        probes: list[AttackPrompt],
        limits: BudgetLimits,
        judge_mode: str,
        target_fingerprint: dict[str, Any],
        redacted: bool = True,
    ) -> None:
        self.planner_name = planner_name
        self.planner_version = planner_version
        self.seed = seed
        self.suite_name = suite.name
        self.suite_hash = compute_suite_hash(suite)
        self.probe_catalog_hash = compute_catalog_hash(probes)
        self.limits = limits
        self.judge_mode = judge_mode
        self.target_fingerprint = target_fingerprint
        self.redacted = redacted
        self.events: list[ReplayEvent] = []

    def record_event(self, event: ReplayEvent) -> None:
        self.events.append(event)

    def build_manifest(self, final_summary: dict[str, Any] | None = None) -> ReplayManifest:
        return ReplayManifest(
            planner_name=self.planner_name,
            planner_version=self.planner_version,
            seed=self.seed,
            suite_name=self.suite_name,
            suite_hash=self.suite_hash,
            probe_catalog_hash=self.probe_catalog_hash,
            limits=self.limits,
            judge_mode=self.judge_mode,
            target_fingerprint=self.target_fingerprint,
            events=list(self.events),
            final_summary=final_summary or {},
            redacted=self.redacted,
        )


class ReplayTarget(Target):
    """Offline, deterministic replay target fulfilling the Target interface."""

    provider = "replay"

    def __init__(
        self,
        manifest: ReplayManifest,
        **kwargs: Any,
    ) -> None:
        super().__init__(model=manifest.target_fingerprint.get("model", "replay-target"), **kwargs)
        self.manifest = manifest
        self._events = list(manifest.events)
        self._cursor = 0

    def _chat_once(self, prompt: str, *, temperature: float, timeout: float) -> str:
        if self._cursor >= len(self._events):
            raise RuntimeError(
                f"ReplayTarget exhausted: requested call {self._cursor + 1} "
                f"but manifest only contains {len(self._events)} events"
            )
        event = self._events[self._cursor]
        self._cursor += 1
        return event.response_text

    async def asend(self, prompt: str, **kwargs: Any) -> str:
        return self._chat_once(prompt, temperature=self.temperature, timeout=self.timeout)

    def fingerprint(self) -> dict[str, Any]:
        fp = dict(self.manifest.target_fingerprint)
        fp["replayed"] = True
        fp["replay_manifest_events"] = len(self._events)
        return fp

    def reset(self) -> None:
        self._cursor = 0


def verify_replay(original: ReplayManifest, replayed: ReplayManifest) -> tuple[bool, str]:
    """Verify that a replayed execution matches the original manifest."""
    if len(original.events) != len(replayed.events):
        return (
            False,
            f"Event count mismatch: original={len(original.events)}, replayed={len(replayed.events)}",
        )

    for i, (orig_ev, rep_ev) in enumerate(zip(original.events, replayed.events, strict=True)):
        if orig_ev.step_id != rep_ev.step_id:
            return (
                False,
                f"Step ID mismatch at index {i}: original={orig_ev.step_id}, replayed={rep_ev.step_id}",
            )
        if orig_ev.probe_id != rep_ev.probe_id:
            return (
                False,
                f"Probe ID mismatch at index {i}: original={orig_ev.probe_id}, replayed={rep_ev.probe_id}",
            )
        if orig_ev.verdict.get("label") != rep_ev.verdict.get("label"):
            return (
                False,
                f"Verdict mismatch at step {orig_ev.step_id}: "
                f"original={orig_ev.verdict.get('label')}, replayed={rep_ev.verdict.get('label')}",
            )

    return True, "Replay verified: byte-identical decision trajectory"


__all__ = [
    "ReplayRecorder",
    "ReplayTarget",
    "compute_catalog_hash",
    "compute_suite_hash",
    "verify_replay",
]
