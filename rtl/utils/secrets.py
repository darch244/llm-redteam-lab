"""Secret scrubbing for reports.

Reports are shared with clients, triagers and occasionally attached to
platform disclosures — they must never contain API keys, bearer tokens or
other live credentials. :func:`scrub` redacts any environment variable the
lab knows about (so a leaked ``OPENAI_API_KEY`` in a response turns into
``<redacted:OPENAI_API_KEY>``) and falls back to evidential key-pattern
matching for anything not in the environment.
"""

from __future__ import annotations

import os
import re
from typing import Any

# Names the lab itself consumes; a value surfaced in a model response is a
# real leak and must be redacted by name.
KNOWN_SECRET_ENV_VARS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OLLAMA_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
    "HUGGINGFACE_API_KEY",
    "GOOGLE_API_KEY",
    "TOGETHER_API_KEY",
    "COHERE_API_KEY",
    "GROQ_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "SLACK_TOKEN",
    "STRIPE_API_KEY",
    "DATADOG_API_KEY",
    "NEW_RELIC_LICENSE_KEY",
    "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN",
]

_PATTERN_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("OPENAI_API_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("ANTHROPIC_API_KEY", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]


def _env_values() -> list[tuple[str, str]]:
    """Return (env_var, value) for every known var that is currently set."""
    return [(name, value) for name in KNOWN_SECRET_ENV_VARS if (value := os.environ.get(name))]


def scrub(text: str) -> str:
    """Replace known secrets and evidential key patterns with redaction markers."""
    out = text
    for name, value in _env_values():
        if value and value in out:
            out = out.replace(value, f"<redacted:{name}>")
    for label, pattern in _PATTERN_RULES:
        out = pattern.sub(f"<redacted:{label}>", out)
    return out


def scrub_dict(data: Any) -> Any:
    """Recursively scrub every string inside a nested structure."""
    if isinstance(data, dict):
        return {key: scrub_dict(value) for key, value in data.items()}
    if isinstance(data, list):
        return [scrub_dict(item) for item in data]
    if isinstance(data, str):
        return scrub(data)
    return data


__all__ = ["KNOWN_SECRET_ENV_VARS", "scrub", "scrub_dict"]
