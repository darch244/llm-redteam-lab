"""Text helpers: truncation, base64 hints, substring matching."""

from __future__ import annotations

import re

# A long, *standalone* base64 token: not embedded in a longer alphanumeric run.
# Requiring the token to be delimited keeps URLs, prose and short hashes from
# tripping the exfil signal while still catching a dumped encoded payload.
_B64_STANDALONE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/=])")

# ``key: value`` evidence lines. The key must be a single identifier-like token
# (no internal spaces) so ordinary numbered instructions such as "Step 1: ..." or
# prose ("Here are the steps:") are NOT mistaken for a secret-dump structure.
_KEY_VALUE_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]*\s*:")


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
    """Heuristic: does the response contain a long, standalone base64 payload?

    Requires a delimited token of at least 64 base64 characters, so a token
    embedded in prose, a URL, or a short hash does not count as evidence.
    """
    return _B64_STANDALONE.search(text) is not None


def looks_like_key_value_lines(text: str, min_pairs: int = 3) -> bool:
    """Heuristic: secret-dump-style ``key: value`` lines.

    Keys must be a single identifier-like token and each line must carry a
    non-empty value, so numbered instructions ("Step 1: ...") or a prose list
    is not mistaken for a structured data dump.
    """
    pairs = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _KEY_VALUE_LINE.match(stripped)
        if match and stripped[match.end() :].strip():
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
