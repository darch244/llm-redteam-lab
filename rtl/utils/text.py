"""Text helpers: truncation, base64 hints, substring matching."""

from __future__ import annotations

import re

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def truncate(text: str, limit: int = 500) -> str:
    """Truncate a string to ``limit`` chars with an ellipsis marker."""
    text = text.strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def contains_any(text: str, needles: list[str]) -> bool:
    """Case-insensitive check for any member of ``needles``."""
    lowered = text.lower()
    return any(n.lower() in lowered for n in needles if n)


def looks_like_base64_blob(text: str) -> bool:
    """Heuristic: is the response mostly a long base64 payload?"""
    candidates = _B64_CANDIDATE.findall(text)
    if not candidates:
        return False
    longest = max(len(match) for match in candidates)
    return longest >= 64


def looks_like_key_value_lines(text: str, min_pairs: int = 3) -> bool:
    """Heuristic: colon-separated key/value pairs on distinct lines."""
    pairs = 0
    for line in text.splitlines():
        if re.match(r"^[A-Za-z0-9_ .-]+\s*:", line.strip()):
            pairs += 1
    return pairs >= min_pairs


def slugify(text: str, max_len: int = 64) -> str:
    """Filesystem-safe slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:max_len] or "untitled"


__all__ = [
    "contains_any",
    "looks_like_base64_blob",
    "looks_like_key_value_lines",
    "slugify",
    "truncate",
]
