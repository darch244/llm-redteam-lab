"""Tool call parsing utilities for different response formats."""

from __future__ import annotations

import json
import re
from typing import Any


class ToolCallParser:
    """Parser for extracting structured tool calls from model responses."""

    @staticmethod
    def parse(response: str) -> list[dict[str, Any]]:
        """Parse tool calls from various formats."""
        parser = ToolCallParser()
        calls = []
        calls.extend(parser._parse_openai_format(response))
        calls.extend(parser._parse_anthropic_format(response))
        calls.extend(parser._parse_json_blocks(response))
        calls.extend(parser._parse_custom_format(response))
        return calls

    def _parse_openai_format(self, text: str) -> list[dict[str, Any]]:
        calls = []
        # Pattern 1: OpenAI function_call with escaped JSON string arguments
        for m in re.finditer(
            r'"function_call"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"arguments"\s*:\s*"((?:\\.|[^"\\])*)"\s*\}',
            text,
            re.DOTALL,
        ):
            try:
                raw_args = m.group(2)
                try:
                    unescaped = json.loads(f'"{raw_args}"')
                    args = json.loads(unescaped) if isinstance(unescaped, str) else unescaped
                except Exception:
                    args = json.loads(raw_args)
                calls.append(
                    {
                        "name": m.group(1),
                        "arguments": args if isinstance(args, dict) else {},
                        "format": "openai",
                    }
                )
            except Exception:
                pass

        # Pattern 2: OpenAI function_call with dictionary arguments directly
        for m in re.finditer(
            r'"function_call"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"arguments"\s*:\s*(\{[^{}]*\})\s*\}',
            text,
            re.DOTALL,
        ):
            try:
                args = json.loads(m.group(2))
                calls.append(
                    {
                        "name": m.group(1),
                        "arguments": args if isinstance(args, dict) else {},
                        "format": "openai",
                    }
                )
            except Exception:
                pass

        # Pattern 3: tool_calls array with function object
        for m in re.finditer(
            r'"tool_calls"\s*:\s*\[\s*\{\s*"id"\s*:\s*"[^"]+"\s*,\s*"type"\s*:\s*"function"\s*,\s*"function"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"arguments"\s*:\s*"((?:\\.|[^"\\])*)"\s*\}\s*\}\s*\]',
            text,
            re.DOTALL,
        ):
            try:
                raw_args = m.group(2)
                try:
                    unescaped = json.loads(f'"{raw_args}"')
                    args = json.loads(unescaped) if isinstance(unescaped, str) else unescaped
                except Exception:
                    args = json.loads(raw_args)
                calls.append(
                    {
                        "name": m.group(1),
                        "arguments": args if isinstance(args, dict) else {},
                        "format": "openai",
                    }
                )
            except Exception:
                pass

        return calls

    def _parse_anthropic_format(self, text: str) -> list[dict[str, Any]]:
        calls = []
        # Anthropic tool use format
        for m in re.finditer(r'<tool_call tool="([^"]+)">(.*?)</tool_call>', text, re.DOTALL):
            try:
                args = json.loads(m.group(2))
                calls.append({"name": m.group(1), "arguments": args, "format": "anthropic"})
            except Exception:
                pass
        return calls

    def _parse_json_blocks(self, text: str) -> list[dict[str, Any]]:
        calls = []
        # JSON code blocks
        for m in re.finditer(r"```json\s*(.*?)\s*```", text, re.DOTALL):
            try:
                data = json.loads(m.group(1))
                if isinstance(data, dict):
                    if "tool" in data or "name" in data:
                        name = data.get("tool") or data.get("name")
                        args = data.get("arguments") or data.get("args") or {}
                        if isinstance(name, str):
                            calls.append(
                                {
                                    "name": name,
                                    "arguments": args if isinstance(args, dict) else {},
                                    "format": "json_block",
                                }
                            )
                    elif "tool_calls" in data and isinstance(data["tool_calls"], list):
                        for item in data["tool_calls"]:
                            if isinstance(item, dict):
                                name = item.get("name") or item.get("tool") or (item.get("function") or {}).get("name")
                                args = item.get("arguments") or {}
                                if isinstance(name, str):
                                    calls.append(
                                        {
                                            "name": name,
                                            "arguments": args if isinstance(args, dict) else {},
                                            "format": "json_block",
                                        }
                                    )
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and ("tool" in item or "name" in item):
                            name = item.get("tool") or item.get("name")
                            args = item.get("arguments") or {}
                            if isinstance(name, str):
                                calls.append(
                                    {
                                        "name": name,
                                        "arguments": args if isinstance(args, dict) else {},
                                        "format": "json_block",
                                    }
                                )
            except Exception:
                pass
        return calls

    def _parse_custom_format(self, text: str) -> list[dict[str, Any]]:
        calls = []
        # Custom format like TOOL_CALL: name(args)
        for m in re.finditer(r"TOOL_CALL:\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\)", text, re.DOTALL):
            name = m.group(1)
            args_str = m.group(2)
            args = {}
            # Try to parse simple args
            for am in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"([^"]*)"', args_str):
                args[am.group(1)] = am.group(2)
            calls.append({"name": name, "arguments": args, "format": "custom"})
        return calls
