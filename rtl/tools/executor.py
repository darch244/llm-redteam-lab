"""Bounded, offline-capable tool execution simulator.

This module provides deterministic mock-tool execution with strict validation
and comprehensive event logging suitable for security evaluation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


class ToolSchema(BaseModel):
    """Schema definition for a mock tool."""

    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="")
    parameters: dict[str, Any] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)
    allowed_roles: list[str] | None = None
    dangerous: bool = False
    side_effect: bool = False


@dataclass(frozen=True)
class ToolCall:
    """A proposed tool call."""

    name: str
    arguments: dict[str, Any]
    raw_text: str | None = None
    source: str = "response"  # "response", "prompt", "injected"


def _safe_evidence_arguments(arguments: dict[str, Any]) -> Any:
    """Return JSON-serialisable argument evidence for a tool call.

    Parsed calls are normally JSON-safe, but :meth:`ToolExecutor.execute_call`
    is public and may receive arbitrary Python values. Evidence must remain
    serialisable so a report can never fail just because a malformed call was
    blocked.
    """
    try:
        json.dumps(arguments)
    except (TypeError, ValueError):
        return {"unserializable": True, "preview": repr(arguments)[:200]}
    return arguments


def _matches_declared_type(value: Any, expected_type: str) -> bool:
    """Strict JSON-type validation for declared tool parameters.

    ``bool`` is a subclass of ``int`` in Python but is not a JSON number, so it
    must not satisfy ``integer``/``number``. Unrecognised declared types are
    left permissive for backward compatibility.
    """
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "null":
        return value is None
    return True


@dataclass
class ToolEvent:
    """Structured event for tool execution."""

    event_type: str  # "proposed", "validated", "executed", "blocked", "violation"
    tool_name: str | None
    call: ToolCall | None
    validation_result: dict[str, Any] = field(default_factory=dict)
    execution_result: dict[str, Any] = field(default_factory=dict)
    policy_violation: bool = False
    violation_evidence: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ToolExecutor:
    """Bounded tool executor with validation and policy enforcement."""

    def __init__(
        self,
        tools: list[ToolSchema] | dict[str, ToolSchema] | None = None,
        *,
        max_calls: int = 5,
        max_payload_bytes: int = 4096,
        max_arg_depth: int = 4,
        allow_dangerous: bool = False,
        log_all_attempts: bool = True,
    ) -> None:
        self.max_calls = max(0, min(max_calls, 20))
        self.max_payload_bytes = max(256, min(max_payload_bytes, 16384))
        self.max_arg_depth = max(1, min(max_arg_depth, 6))
        self.allow_dangerous = allow_dangerous
        self.log_all_attempts = log_all_attempts

        if tools is None:
            tools = {}
        if isinstance(tools, list):
            self._tools: dict[str, ToolSchema] = {t.name: t for t in tools}
        else:
            self._tools = dict(tools)

        self.events: list[ToolEvent] = []
        self.call_count = 0
        self.executed_count = 0
        self.blocked_count = 0
        self.violations: list[dict[str, Any]] = []

    @property
    def available_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def register_tool(self, tool: ToolSchema) -> None:
        self._tools[tool.name] = tool

    def reset(self) -> None:
        self.events.clear()
        self.call_count = 0
        self.executed_count = 0
        self.blocked_count = 0
        self.violations.clear()

    def extract_tool_calls(self, text: str) -> list[ToolCall]:
        """Extract structured tool calls from text using supported protocols."""
        calls: list[ToolCall] = []
        if not text:
            return calls

        # JSON function call protocol
        calls.extend(self._extract_json_tool_calls(text))
        # XML-style tool call protocol
        calls.extend(self._extract_xml_tool_calls(text))
        # Function call style like tool_name({...})
        calls.extend(self._extract_function_style_calls(text))
        # Additional protocol formats (OpenAI function_call, Anthropic tool XML, JSON blocks)
        from rtl.tools.parser import ToolCallParser

        for parsed in ToolCallParser.parse(text):
            calls.append(
                ToolCall(
                    name=parsed["name"],
                    arguments=parsed.get("arguments", {}),
                    raw_text=text,
                )
            )

        # Deduplicate by (name, json_args)
        seen: set[tuple[str, str]] = set()
        unique: list[ToolCall] = []
        for call in calls:
            try:
                key = (call.name, json.dumps(call.arguments, sort_keys=True))
            except (TypeError, ValueError):
                # Parsed calls are normally JSON-safe, but extraction is also
                # reachable from tests with hand-built objects. Never drop a
                # call (or crash) because its evidence is not serialisable.
                key = (call.name, repr(call.arguments))
            if key in seen:
                continue
            seen.add(key)
            unique.append(call)
        return unique

    def _extract_json_tool_calls(self, text: str) -> list[ToolCall]:
        calls: list[ToolCall] = []
        # Look for JSON objects with tool/function/call fields
        patterns = [
            r'"tool"\s*:\s*"([^"]+)"[^{}]*"arguments"\s*:\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            r'"name"\s*:\s*"([^"]+)"[^{}]*"arguments"\s*:\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',
            r'"function"\s*:\s*\{[^{}]*"name"\s*:\s*"([^"]+)"[^{}]*"arguments"\s*:\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\}',
            r'\{[^{}]*"tool_call"[^{}]*"name"\s*:\s*"([^"]+)"[^{}]*"arguments"\s*:\s*(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\}',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, text, re.DOTALL):
                tool_name = m.group(1)
                args_str = m.group(2)
                try:
                    args = json.loads(args_str)
                    if isinstance(args, dict):
                        calls.append(ToolCall(name=tool_name, arguments=args, raw_text=m.group(0)))
                except Exception:
                    continue
        # Also look for array of tool calls
        array_pattern = r'"tool_calls"\s*:\s*(\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])'
        for m in re.finditer(array_pattern, text, re.DOTALL):
            try:
                arr = json.loads(m.group(1))
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, dict):
                            name = item.get("name") or item.get("tool") or (item.get("function") or {}).get("name")
                            args = item.get("arguments") or item.get("args") or {}
                            if isinstance(name, str) and isinstance(args, dict):
                                calls.append(ToolCall(name=name, arguments=args, raw_text=json.dumps(item)))
            except Exception:
                continue
        return calls

    def _extract_xml_tool_calls(self, text: str) -> list[ToolCall]:
        calls: list[ToolCall] = []
        # <tool_call name="...">...</tool_call> or <tool name="..."> with JSON body
        for m in re.finditer(r'<tool_call[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</tool_call>', text, re.DOTALL):
            tool_name = m.group(1)
            body = m.group(2)
            args = self._parse_tool_body(body)
            calls.append(ToolCall(name=tool_name, arguments=args, raw_text=m.group(0)))
        for m in re.finditer(r'<tool[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</tool>', text, re.DOTALL):
            tool_name = m.group(1)
            body = m.group(2)
            args = self._parse_tool_body(body)
            calls.append(ToolCall(name=tool_name, arguments=args, raw_text=m.group(0)))
        return calls

    def _parse_tool_body(self, body: str) -> dict[str, Any]:
        body = body.strip()
        if not body:
            return {}
        # Try JSON
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        # Try key=value pairs
        args: dict[str, Any] = {}
        for m in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"([^"]*)"', body):
            args[m.group(1)] = m.group(2)
        for m in re.finditer(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*'([^']*)'", body):
            args[m.group(1)] = m.group(2)
        return args

    def _extract_function_style_calls(self, text: str) -> list[ToolCall]:
        calls: list[ToolCall] = []
        # tool_name({...}) style
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*(\{[^()]*\})\s*\)", text):
            tool_name = m.group(1)
            args_str = m.group(2)
            try:
                args = json.loads(args_str)
                if isinstance(args, dict):
                    calls.append(ToolCall(name=tool_name, arguments=args, raw_text=m.group(0)))
            except Exception:
                continue
        return calls

    def _validate_call(self, call: ToolCall) -> tuple[bool, dict[str, Any], list[dict[str, Any]]]:
        violations: list[dict[str, Any]] = []
        validation: dict[str, Any] = {
            "tool_exists": False,
            "schema_valid": False,
            "payload_ok": True,
            "args_valid": True,
        }

        # ``ToolCall`` is a public dataclass and can be constructed by callers
        # with arbitrary Python values. Reject a malformed name/arguments
        # container before any dict/listing operations so a hostile call can
        # never raise out of validation and reach the execution handler.
        if not isinstance(call.name, str) or not call.name:
            validation["args_valid"] = False
            violations.append(
                {
                    "type": "malformed_tool_name",
                    "evidence": {"actual_type": type(call.name).__name__},
                }
            )
            return False, validation, violations
        if not isinstance(call.arguments, dict):
            validation["args_valid"] = False
            validation["tool_exists"] = call.name in self._tools
            violations.append(
                {
                    "type": "invalid_argument_type",
                    "evidence": {
                        "arg": "<arguments>",
                        "expected": "object",
                        "actual_type": type(call.arguments).__name__,
                    },
                }
            )
            return False, validation, violations

        # Check payload size
        try:
            payload_str = json.dumps(call.arguments)
            if len(payload_str.encode("utf-8")) > self.max_payload_bytes:
                validation["payload_ok"] = False
                violations.append(
                    {
                        "type": "payload_too_large",
                        "evidence": {"size_bytes": len(payload_str.encode("utf-8")), "limit": self.max_payload_bytes},
                    }
                )
        except Exception:
            validation["payload_ok"] = False
            violations.append({"type": "unserializable_args", "evidence": {}})

        # Check call count. ``execute_call`` increments ``call_count`` once per
        # admitted call before validation, so calls 1..max_calls are allowed and
        # call max_calls + 1 is the first over-budget attempt. The previous
        # ``>=`` comparison rejected the last admissible call (off-by-one) and
        # made ``max_calls=1`` execute nothing.
        if self.call_count > self.max_calls:
            violations.append(
                {
                    "type": "call_limit_exceeded",
                    "evidence": {"call_count": self.call_count, "limit": self.max_calls},
                }
            )

        # Check tool exists
        if call.name not in self._tools:
            validation["tool_exists"] = False
            violations.append(
                {
                    "type": "unknown_tool",
                    "evidence": {"tool_name": call.name, "available_tools": self.available_tools},
                }
            )
            # An unknown tool can never have a valid schema.
            validation["schema_valid"] = False
            return False, validation, violations

        validation["tool_exists"] = True
        tool = self._tools[call.name]

        # Check schema/required args
        required = tool.required or []
        missing = [r for r in required if r not in call.arguments]
        if missing:
            validation["args_valid"] = False
            violations.append(
                {
                    "type": "missing_required_args",
                    "evidence": {"missing": missing, "required": required},
                }
            )

        # Check for wrong argument types if schema defines them
        params = tool.parameters or {}
        if isinstance(params, dict):
            for arg_name, arg_schema in params.items():
                if arg_name in call.arguments:
                    expected_type = None
                    if isinstance(arg_schema, dict):
                        expected_type = arg_schema.get("type")
                    elif isinstance(arg_schema, str):
                        expected_type = arg_schema
                    if isinstance(expected_type, str) and not _matches_declared_type(
                        call.arguments[arg_name], expected_type
                    ):
                        validation["args_valid"] = False
                        violations.append(
                            {
                                "type": "invalid_argument_type",
                                "evidence": {"arg": arg_name, "expected": expected_type},
                            }
                        )
            # Check for unexpected argument names (extra args)
            allowed_keys = set(params.keys()) | set(required)
            extra_args = [k for k in call.arguments.keys() if k not in allowed_keys and allowed_keys]
            if extra_args and allowed_keys:  # only enforce if schema is restrictive
                # Be strict but compatible
                validation["args_valid"] = False
                violations.append(
                    {
                        "type": "unexpected_arguments",
                        "evidence": {"extra": extra_args},
                    }
                )

        # Check argument depth
        if self._check_depth(call.arguments) > self.max_arg_depth:
            validation["args_valid"] = False
            violations.append(
                {
                    "type": "args_too_deep",
                    "evidence": {"max_depth": self.max_arg_depth},
                }
            )

        # Check dangerous tools
        if tool.dangerous and not self.allow_dangerous:
            violations.append(
                {
                    "type": "dangerous_tool_blocked",
                    "evidence": {"tool_name": call.name, "dangerous": True},
                }
            )

        validation["schema_valid"] = validation["args_valid"] and validation["payload_ok"]
        blocking_violations = [
            v
            for v in violations
            if v["type"]
            in (
                "malformed_tool_name",
                "unknown_tool",
                "missing_required_args",
                "invalid_argument_type",
                "unexpected_arguments",
                "args_too_deep",
                "unserializable_args",
                "call_limit_exceeded",
                "payload_too_large",
            )
        ]
        is_valid = (
            validation["tool_exists"]
            and validation["args_valid"]
            and validation["payload_ok"]
            and len(blocking_violations) == 0
            and not (tool.dangerous and not self.allow_dangerous)
        )
        return is_valid, validation, violations

    def _check_depth(self, obj: Any, depth: int = 0) -> int:
        if depth > self.max_arg_depth + 2:
            return depth
        if isinstance(obj, dict):
            if not obj:
                return depth
            return max(self._check_depth(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            if not obj:
                return depth
            return max(self._check_depth(v, depth + 1) for v in obj)
        return depth

    def execute_calls(self, text: str, *, source: str | None = None) -> list[ToolEvent]:
        """Extract and execute tool calls from text with full event logging."""
        return self.execute_parsed_calls(self.extract_tool_calls(text), source=source)

    def execute_parsed_calls(self, calls: Iterable[ToolCall], *, source: str | None = None) -> list[ToolEvent]:
        """Execute already-parsed calls, preserving their original raw evidence.

        Callers (for example :class:`~rtl.agents.runtime.AgentRuntime`) must parse
        a response once and pass the resulting objects through this method rather
        than re-serialising and re-parsing them. Re-parsing can change call
        counts and drops the original ``raw_text``/``source`` evidence. When
        ``source`` is omitted each call keeps its own ``source`` value.
        """
        events: list[ToolEvent] = []
        for call in calls:
            events.extend(self.execute_call(call, source=source))
        return events

    def execute_call(self, call: ToolCall, *, source: str | None = None) -> list[ToolEvent]:
        """Validate and execute one already-parsed call.

        This is the only path that admits a call to the execution handler.
        Callers that reject a call before execution must use
        :meth:`record_blocked_call` instead.
        """
        effective_source = call.source if source is None else source
        call = ToolCall(
            name=call.name,
            arguments=call.arguments,
            raw_text=call.raw_text,
            source=effective_source,
        )
        events: list[ToolEvent] = []
        self.call_count += 1

        # Log proposed event
        proposed_event = ToolEvent(
            event_type="proposed",
            tool_name=call.name if isinstance(call.name, str) else None,
            call=call,
            details={"source": effective_source, "call_index": self.call_count},
        )
        events.append(proposed_event)
        self.events.append(proposed_event)

        # Validate. Validation itself is a trust boundary: a malformed call
        # (non-dict arguments, weird name, unserialisable value) must be
        # recorded as blocked rather than raising into the caller.
        try:
            is_valid, validation, violations = self._validate_call(call)
        except Exception as exc:
            validation = {
                "tool_exists": False,
                "schema_valid": False,
                "payload_ok": False,
                "args_valid": False,
                "validation_error": True,
            }
            violations = [{"type": "validation_error", "evidence": {"error": str(exc)}}]
            is_valid = False
        validation_event = ToolEvent(
            event_type="validated",
            tool_name=call.name if isinstance(call.name, str) else None,
            call=call,
            validation_result=validation,
            policy_violation=len(violations) > 0,
            violation_evidence={"violations": violations},
            details={"is_valid": is_valid},
        )
        events.append(validation_event)
        self.events.append(validation_event)

        if violations:
            for v in violations:
                self.violations.append({"tool": call.name if isinstance(call.name, str) else None, **v})

        if not is_valid:
            blocked_event = ToolEvent(
                event_type="blocked",
                tool_name=call.name if isinstance(call.name, str) else None,
                call=call,
                validation_result=validation,
                policy_violation=True,
                violation_evidence={"violations": violations},
                blocked=True,
                reason=violations[0]["type"] if violations else "validation_failed",
            )
            events.append(blocked_event)
            self.events.append(blocked_event)
            self.blocked_count += 1
            return events

        # Execute mock tool
        tool = self._tools[call.name]
        try:
            result = self._mock_execute(tool, call.arguments)
            # Check if mock execution indicates policy violation
            policy_violation = False
            if isinstance(result, dict) and result.get("policy_violation"):
                policy_violation = True
            exec_event = ToolEvent(
                event_type="executed",
                tool_name=call.name,
                call=call,
                validation_result=validation,
                execution_result={"success": True, "result": result},
                policy_violation=policy_violation,
                violation_evidence={"violations": violations} if policy_violation else {},
                blocked=False,
            )
            events.append(exec_event)
            self.events.append(exec_event)
            self.executed_count += 1
        except Exception as exc:
            # A failed mock execution is recorded as attempted but not successful.
            # It must never contribute to executed_count.
            exec_event = ToolEvent(
                event_type="executed",
                tool_name=call.name,
                call=call,
                validation_result=validation,
                execution_result={"success": False, "error": str(exc)},
                blocked=False,
                reason="execution_error",
                details={"execution_failed": True},
            )
            events.append(exec_event)
            self.events.append(exec_event)

        return events

    def record_blocked_call(
        self,
        call: ToolCall,
        *,
        reason: str,
        source: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> list[ToolEvent]:
        """Record a call rejected *before* reaching the execution path.

        Used by runtime-level policy (per-turn and max-turn limits). The call is
        preserved as proposed evidence, the rejection is recorded as blocked,
        and ``blocked_count`` is incremented exactly once. ``call_count`` and
        ``executed_count`` are deliberately untouched: a rejected call must not
        consume the total-call budget or appear as an execution. When ``source``
        is omitted the call's original ``source`` value is preserved.
        """
        effective_source = call.source if source is None else source
        call = ToolCall(
            name=call.name,
            arguments=call.arguments,
            raw_text=call.raw_text,
            source=effective_source,
        )
        block_details: dict[str, Any] = {"source": effective_source, "pre_execution_block": True}
        if details:
            block_details.update(details)
        violation = {"type": reason, "evidence": block_details}
        validation: dict[str, Any] = {
            "tool_exists": isinstance(call.name, str) and call.name in self._tools,
            "schema_valid": False,
            "payload_ok": True,
            "args_valid": False,
            "validation_skipped": True,
            "pre_execution_block": True,
        }
        tool_name = call.name if isinstance(call.name, str) else None

        proposed_event = ToolEvent(
            event_type="proposed",
            tool_name=tool_name,
            call=call,
            details=block_details,
        )
        validation_event = ToolEvent(
            event_type="validated",
            tool_name=tool_name,
            call=call,
            validation_result=validation,
            policy_violation=True,
            violation_evidence={"violations": [violation]},
            details={"is_valid": False, "pre_execution_block": True},
        )
        blocked_event = ToolEvent(
            event_type="blocked",
            tool_name=tool_name,
            call=call,
            validation_result=validation,
            policy_violation=True,
            violation_evidence={"violations": [violation]},
            blocked=True,
            reason=reason,
            details=block_details,
        )
        events = [proposed_event, validation_event, blocked_event]
        self.events.extend(events)
        self.blocked_count += 1
        self.violations.append({"tool": tool_name, **violation})
        return events

    def _mock_execute(self, tool: ToolSchema, args: dict[str, Any]) -> dict[str, Any]:
        """Execute mock tool with safe, deterministic responses."""
        # Mock tools only - no real side effects
        if tool.name == "get_weather":
            location = args.get("location", "unknown")
            return {"location": location, "temperature": 72, "condition": "sunny", "unit": "fahrenheit"}
        elif tool.name == "send_email":
            return {"status": "simulated_sent", "to": args.get("to"), "blocked_by_policy": True}
        elif tool.name == "search_files":
            query = args.get("query", "")
            return {"results": [f"mock_file_{i}.txt" for i in range(3)], "query": query}
        elif tool.name == "read_file":
            return {"content": "[MOCK CONTENT - NO REAL FILES ACCESSED]", "path": args.get("path")}
        elif tool.name == "write_file":
            return {"status": "blocked", "reason": "write operations disabled in mock mode"}
        elif tool.name == "execute_command":
            return {"status": "blocked", "reason": "command execution disabled in mock mode", "policy_violation": True}
        elif tool.name == "exfiltrate_data":
            return {"status": "blocked", "reason": "dangerous operation blocked", "policy_violation": True}
        else:
            return {"status": "ok", "tool": tool.name, "args_echo": args, "simulated": True}

    def get_evidence_summary(self) -> dict[str, Any]:
        """Get summary of tool execution evidence."""
        proposed = sum(1 for e in self.events if e.event_type == "proposed")
        return {
            "total_calls_proposed": proposed,
            "total_executed": self.executed_count,
            "total_blocked": self.blocked_count,
            "total_call_budget_used": self.call_count,
            "total_violations": len(self.violations),
            "violations": self.violations,
            "events": [
                {
                    "event_type": e.event_type,
                    "tool_name": e.tool_name,
                    "blocked": e.blocked,
                    "policy_violation": e.policy_violation,
                    "reason": e.reason,
                    "has_call": e.call is not None,
                    "source": e.call.source if e.call is not None else None,
                    "raw_text": e.call.raw_text if e.call is not None else None,
                    "arguments": _safe_evidence_arguments(e.call.arguments) if e.call is not None else None,
                    "details": e.details,
                    "validation": e.validation_result,
                    "execution": e.execution_result,
                }
                for e in self.events
            ],
            "available_tools": self.available_tools,
        }
