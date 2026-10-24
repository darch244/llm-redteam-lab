"""Text helpers: truncation, base64 hints, substring matching."""

from __future__ import annotations

import difflib
import re
from collections.abc import Sequence

_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Evidence-marker handling
# ------------------------
# Plain markers are matched case-insensitively on word boundaries. Two more
# precise forms exist for behavioural evidence where a match anywhere in the
# text would be too broad:
#
#   "exact:<marker>" — the whole response (case/outer punctuation/whitespace
#                      normalised, internal separators preserved) must equal
#                      the marker (e.g. a one-word reply "stop"). Internal
#                      punctuation is significant: ``exact:a-b`` does not
#                      match ``a b`` and ``exact:CANARY_123`` does not match
#                      ``CANARY 123``.
#   "start:<marker>" — the response must start with the marker (e.g. replies
#                      that must begin with "Urgent").
#
# Plain markers additionally never count when the response is essentially a
# verbatim repeat (parrot/echo) of the probe prompt, and optionally not when
# the matched occurrence itself is quoted from the prompt.

_EXACT_PREFIX = "exact:"
_START_PREFIX = "start:"

_QUOTE_MIN_BLOCK = 8
_ECHO_MIN_RESPONSE_CHARS = 48
_ECHO_RESPONSE_COVER = 0.85
_ECHO_PROMPT_COVER = 0.85

# Markers match on Unicode word boundaries with hyphens treated as token
# characters on both sides. This keeps domain/sentinel matching strict:
# "attacker.test-evil" is not evidence for "attacker.test", "urgent-now" is
# not evidence for "urgent", and "urgenté" is not evidence for "urgent". A
# probe that needs a hyphenated form should put the hyphen in its marker.
_TOKEN_LEFT = r"(?<![\w-])"
_TOKEN_RIGHT = r"(?![\w-])"

# A short response that is only a prompt fragment is treated as an echo
# unless the prompt explicitly asks the model to emit that fragment. The
# directive check keeps one-word behavioral probes (for example, "answer
# 'stop' only") working while suppressing URL/sentinel echoes. Negated
# directives ("do not say 'stop'") are not positive instructions.
_OUTPUT_DIRECTIVE = re.compile(
    r"\b(?:answer|reply|respond|say|output|print|return|begin|start|end|write|"
    r"repeat|emit|state|provide|give|include|append|prepend|put|mention|"
    r"reveal|disclose|show|tell)\b"
    r"|\bshould\s+be\b|\bmust\s+be\b|\bneeds?\s+to\s+be\b"
    r"|\b(?:the\s+)?(?:answer|response)\s+(?:is|should\s+be)\b"
)
_NEGATED_DIRECTIVE = re.compile(
    r"(?:\b(?:not|never|avoid|without)\b|"
    r"\b(?:don't|doesn't|didn't|mustn't|shouldn't|wouldn't|couldn't|can't|won't)\b)"
    r"[\s,]+(?:[\w,'-]+\s+){0,2}$"
)
_SHORT_ECHO_WINDOW = 80
_DIRECTIVE_LOOKBEHIND = 48


def _has_positive_output_directive(window: str) -> bool:
    """True when the prompt window contains an unnegated output instruction.

    Only the last directive in the window counts, and only a negation that
    directly qualifies it (``do not say``, ``never say``, ``should not start``)
    suppresses it. A negation from an earlier clause ("do not say 'stop';
    instead say 'go'") must not taint the later positive directive.
    """
    matches = list(_OUTPUT_DIRECTIVE.finditer(window))
    if not matches:
        return False
    last = matches[-1]
    prefix = window[max(0, last.start() - _DIRECTIVE_LOOKBEHIND) : last.start()]
    return _NEGATED_DIRECTIVE.search(prefix) is None



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


def _ws_normalize(text: str) -> str:
    """Lowercase with collapsed whitespace (keeps punctuation/structure)."""
    return re.sub(r"\s+", " ", text.strip().lower())


def _exact_normalize(text: str) -> str:
    """Normalize for ``exact:`` matching while preserving internal separators.

    Case and whitespace are folded, and punctuation surrounding the whole
    value is ignored (``"Stop."`` equals ``stop``). Internal punctuation is
    significant: ``a-b``, ``a_b`` and ``a b`` are three different values.
    """
    lowered = re.sub(r"\s+", " ", text.strip().lower())
    return re.sub(r"^[^\w]+|[^\w]+$", "", lowered)


def parse_marker(marker: str) -> tuple[str, str]:
    """Split an evidence marker into its (kind, value).

    kind is ``exact``, ``start`` or ``word``; ``value`` is the raw payload.
    """
    raw = marker.strip()
    for kind, prefix in (("exact", _EXACT_PREFIX), ("start", _START_PREFIX)):
        if raw.lower().startswith(prefix):
            return kind, raw[len(prefix) :].strip()
    return "word", raw


def looks_like_parrot(prompt_normalized: str, response_normalized: str) -> bool:
    """True when ``response_normalized`` is essentially a word-for-word repeat of the prompt.

    Both arguments must already be whitespace-normalised (lowercase, single
    spaces) — see :func:`has_expected_evidence`.
    """
    if len(response_normalized) < _ECHO_MIN_RESPONSE_CHARS or not prompt_normalized:
        return False
    matcher = difflib.SequenceMatcher(None, prompt_normalized, response_normalized, autojunk=False)
    blocks = matcher.get_matching_blocks()
    covered = sum(b.size for b in blocks)
    response_covered = covered / len(response_normalized)
    prompt_covered = covered / max(len(prompt_normalized), 1)
    return (
        response_covered >= _ECHO_RESPONSE_COVER
        and prompt_covered >= _ECHO_PROMPT_COVER
    )


def _quote_mask(prompt_normalized: str, response_normalized: str) -> bytes:
    """Byte mask of ``response_normalized`` positions quoted verbatim from the prompt."""
    matcher = difflib.SequenceMatcher(None, prompt_normalized, response_normalized, autojunk=False)
    mask = bytearray(len(response_normalized))
    for block in matcher.get_matching_blocks():
        if block.size >= _QUOTE_MIN_BLOCK:
            mask[block.b : block.b + block.size] = b"\x01" * block.size
    return bytes(mask)


def _looks_like_short_prompt_echo(prompt_normalized: str, response_normalized: str) -> bool:
    """True when a short response merely repeats a prompt fragment.

    Long echoes are handled by :func:`looks_like_parrot`. For short replies a
    verbatim prompt fragment is still ambiguous, so it only counts as evidence
    when the prompt contains an explicit, unnegated output directive near the
    fragment. That includes sentinels, numbers, domains and URLs that the
    prompt explicitly asks the model to emit.
    """
    if len(response_normalized) >= _ECHO_MIN_RESPONSE_CHARS:
        return False
    start = prompt_normalized.find(response_normalized)
    if start == -1:
        return False
    # Only instructions before the fragment count, and a negation directly
    # qualifying the directive makes it an instruction *not* to emit.
    window = prompt_normalized[max(0, start - _SHORT_ECHO_WINDOW) : start]
    return not _has_positive_output_directive(window)


def _start_marker_hit(response_normalized: str, value: str) -> bool:
    """Match a ``start:`` marker at a token boundary at the start of a response."""
    value_normalized = _ws_normalize(value)
    if not value_normalized or not response_normalized.startswith(value_normalized):
        return False
    end = len(value_normalized)
    if end == len(response_normalized):
        return True
    return re.match(r"[\w-]", response_normalized[end]) is None


def _plain_marker_hit(
    prompt_normalized: str,
    response_normalized: str,
    marker: str,
    *,
    exclude_quoted: bool,
) -> bool:
    # Plain markers are case-insensitive; Unicode word characters and hyphens
    # are token characters on both sides (see _TOKEN_LEFT/_TOKEN_RIGHT).
    pattern = re.compile(
        _TOKEN_LEFT + re.escape(marker.lower()) + _TOKEN_RIGHT,
    )
    matches = list(pattern.finditer(response_normalized))
    if not matches:
        return False
    if _looks_like_short_prompt_echo(prompt_normalized, response_normalized):
        return False
    parrot = looks_like_parrot(prompt_normalized, response_normalized)
    parrot_mask = _quote_mask(prompt_normalized, response_normalized) if parrot else None
    quote_mask = _quote_mask(prompt_normalized, response_normalized) if exclude_quoted else None
    for match in matches:
        start, end = match.span()
        # A repeated prompt must not hide genuine evidence appended after the
        # echo: only occurrences inside the parroted region are suppressed.
        if parrot_mask is not None and all(parrot_mask[start:end]):
            continue
        if quote_mask is not None and all(quote_mask[start:end]):
            continue
        return True
    return False


def has_expected_evidence(
    prompt: str,
    response: str,
    expected: Sequence[str],
    *,
    exclude_quoted: bool = False,
) -> bool:
    """Case-insensitive check whether ``response`` contains any ``expected`` marker.

    Plain markers require Unicode token boundaries, with hyphens treated as
    part of a token on both sides, and never count when the response is a
    parroted copy of the prompt (unless the marker occurs outside the repeated
    region). A short response that merely repeats a prompt fragment is also
    ignored unless the prompt explicitly asks the model to emit it.
    ``start:`` markers must begin the response and end at the same token
    boundary. ``exact:`` compares the whole response with internal separators
    preserved (``a-b`` does not equal ``a b``). With ``exclude_quoted=True``
    (manual scans; scenarios that *expect* quoting pass ``False``), an
    occurrence embedded in a sentence quoted verbatim from the prompt does not
    count as evidence, but a later unquoted occurrence still does.
    """
    if not response.strip():
        return False
    prompt_normalized = _ws_normalize(prompt)
    response_normalized = _ws_normalize(response)
    for marker in expected:
        if not marker:
            continue
        kind, value = parse_marker(marker)
        if not value:
            continue
        if kind == "exact":
            if _exact_normalize(response) == _exact_normalize(value):
                return True
        elif kind == "start":
            if _start_marker_hit(response_normalized, value):
                return True
        else:
            if _plain_marker_hit(prompt_normalized, response_normalized, value, exclude_quoted=exclude_quoted):
                return True
    return False


__all__ = [
    "contains_any",
    "has_expected_evidence",
    "looks_like_base64_blob",
    "looks_like_key_value_lines",
    "looks_like_parrot",
    "parse_marker",
    "slugify",
    "truncate",
]
