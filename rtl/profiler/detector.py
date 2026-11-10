"""Target capability detection and dynamic profile updating."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from rtl.logging import get_logger
from rtl.profiler.models import CapabilityConfidence, CapabilityName, TargetProfile

if TYPE_CHECKING:
    from rtl.planning.models import Observation
    from rtl.targets.base import Target

log = get_logger("profiler.detector")


class PassiveProfiler:
    """Updates TargetProfile monotonically from runtime execution evidence."""

    @classmethod
    def update_from_observation(
        cls,
        profile: TargetProfile,
        observation: Observation,
        raw: dict[str, Any] | None = None,
    ) -> None:
        raw = raw or {}

        # 1. Tool execution and function calling telemetry
        has_tool_execution = raw.get("has_tool_execution", False)
        has_tool_attempt = raw.get("has_tool_call_attempt", False) or raw.get("tool_calls_proposed", 0) > 0
        tool_events = raw.get("tool_events", [])

        if has_tool_execution:
            profile.record_evidence(
                CapabilityName.TOOL_ACCESS,
                CapabilityConfidence.OBSERVED,
                evidence_id=observation.step_id,
                note="Tool execution completed in runtime simulation",
            )
            profile.record_evidence(
                CapabilityName.FUNCTION_CALLING,
                CapabilityConfidence.OBSERVED,
                evidence_id=observation.step_id,
                note="Target emitted callable function invocation syntax",
            )

            # Inspect specific tool types
            for event in tool_events:
                t_name = str(event.get("tool") or "").lower()
                if "browse" in t_name or "fetch" in t_name or "http" in t_name:
                    profile.record_evidence(
                        CapabilityName.BROWSER_ACCESS,
                        CapabilityConfidence.OBSERVED,
                        evidence_id=observation.step_id,
                        note=f"Invoked browsing/fetching tool '{t_name}'",
                    )
                if "execute" in t_name or "command" in t_name or "bash" in t_name:
                    profile.record_evidence(
                        CapabilityName.CODE_EXECUTION,
                        CapabilityConfidence.OBSERVED,
                        evidence_id=observation.step_id,
                        note=f"Invoked command execution tool '{t_name}'",
                    )
        elif has_tool_attempt:
            profile.record_evidence(
                CapabilityName.FUNCTION_CALLING,
                CapabilityConfidence.INFERRED,
                evidence_id=observation.step_id,
                note="Target emitted tool syntax without successful execution",
            )

        # 2. Scenario-specific capability evidence
        cat = observation.category
        if cat == "rag_poisoning" or "retrieved_docs" in raw:
            profile.record_evidence(
                CapabilityName.RAG,
                CapabilityConfidence.OBSERVED,
                evidence_id=observation.step_id,
                note="Target executed retrieval augmentation context pipeline",
            )
            profile.record_evidence(
                CapabilityName.RETRIEVAL,
                CapabilityConfidence.OBSERVED,
                evidence_id=observation.step_id,
            )

        if cat == "memory_poisoning":
            profile.record_evidence(
                CapabilityName.MEMORY,
                CapabilityConfidence.OBSERVED,
                evidence_id=observation.step_id,
                note="Target utilized conversational or external memory buffer",
            )

        # 3. Guardrails detection
        if observation.verdict.label == "refused":
            profile.record_evidence(
                CapabilityName.GUARDRAILS,
                CapabilityConfidence.OBSERVED,
                evidence_id=observation.step_id,
                note=f"Target triggered explicit safety refusal guardrail: {observation.verdict.reason[:150]}",
            )

        # 4. Structured output detection
        text = observation.response_excerpt.strip()
        if text.startswith("{") and text.endswith("}"):
            try:
                json.loads(text)
                profile.record_evidence(
                    CapabilityName.STRUCTURED_OUTPUT,
                    CapabilityConfidence.OBSERVED,
                    evidence_id=observation.step_id,
                    note="Target emitted valid JSON object",
                )
            except Exception:
                pass


class ActiveProfiler:
    """Non-destructive diagnostic probes to determine target capabilities pre-campaign."""

    @classmethod
    async def profile_target(
        cls,
        target: Target,
        target_id: str | None = None,
    ) -> TargetProfile:
        fp = target.fingerprint()
        provider = fp.get("provider", "unknown")
        model = fp.get("model", "unknown")
        tid = target_id or f"{provider}:{model}"
        profile = TargetProfile(target_id=tid, provider=provider, model=model)

        # Provider-based known capabilities
        if provider == "openai":
            profile.record_evidence(
                CapabilityName.FUNCTION_CALLING, CapabilityConfidence.KNOWN, note="OpenAI API default"
            )
            profile.record_evidence(
                CapabilityName.STRUCTURED_OUTPUT, CapabilityConfidence.KNOWN, note="OpenAI JSON mode"
            )
        elif provider == "anthropic":
            profile.record_evidence(
                CapabilityName.FUNCTION_CALLING, CapabilityConfidence.KNOWN, note="Anthropic tools API"
            )

        # Run minimal benign discovery prompt
        discovery_prompt = (
            'Hello! Please respond with a valid JSON object formatted as {"status": "ready", "capabilities": ["text"]}.'
        )
        try:
            resp = await target.asend(discovery_prompt)
            if resp:
                resp_clean = resp.strip()
                # An echo of the prompt does not constitute evidence of structured generation
                if discovery_prompt.strip() not in resp_clean and "{" in resp_clean and "}" in resp_clean:
                    try:
                        start_idx = resp_clean.find("{")
                        end_idx = resp_clean.rfind("}") + 1
                        candidate_json = resp_clean[start_idx:end_idx]
                        parsed = json.loads(candidate_json)
                        if isinstance(parsed, dict) and bool(parsed):
                            profile.record_evidence(
                                CapabilityName.STRUCTURED_OUTPUT,
                                CapabilityConfidence.OBSERVED,
                                note="Target emitted valid structured JSON response to diagnostic probe",
                            )
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("Active capability profiling encounter: %s", exc)

        return profile


__all__ = ["ActiveProfiler", "PassiveProfiler"]
