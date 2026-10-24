"""Secret scrubbing for reports.

Reports are shared with clients, triagers and occasionally attached to
platform disclosures — they must never contain API keys, bearer tokens or
other live credentials. :func:`scrub` redacts any environment variable the
lab knows about (so a leaked ``OPENAI_API_KEY`` in a response turns into
``<redacted:OPENAI_API_KEY>``) and falls back to evidential key-pattern
matching for anything not in the environment.

Credential environment values are matched wherever they occur once past a
minimum length. Descriptive deployment values are matched on token boundaries
(short plain-word values are ignored); without that policy a deployment name
such as ``prod`` would corrupt ordinary prose (``production is ready`` ->
``<redacted:AZURE_OPENAI_DEPLOYMENT>uction is ready``).
"""

from __future__ import annotations

import datetime as _datetime
import os
import pathlib
import re
from collections.abc import Callable, Mapping
from typing import Any

from rtl.utils.text import truncate

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

# Values that identify an endpoint/deployment rather than authenticate. A
# short plain word (``prod``, ``staging``, ``gpt4o``) is legitimate prose and
# must not be treated as a credential.
_NON_CREDENTIAL_ENV_VARS = frozenset({"AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT"})
_MIN_ENV_VALUE_LEN = 6
_MIN_PLAIN_ENV_WORD_LEN = 12

_PATTERN_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("OPENAI_API_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("ANTHROPIC_API_KEY", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]

# Secret-like *values* in URL query strings are redacted while the rest of the
# URL (host, path, safe parameters like ?page=2) is preserved verbatim.
# Requires an optional suffix/prefix name segment at a separator boundary so
# similar-but-benign keys ("tokenize=1", "monkey=1") are untouched.
_QUERY_SECRET_VALUE = re.compile(
    r"(?i)([?&#]([a-z0-9]*[-_.])?"
    r"(?:api_?key|apikey|access_?token|auth_?token|refresh_?token|"
    r"secret|password|passwd|pwd|signature|token|key)"
    r"=)([^&\s#]+)"
)
_QUERY_SECRET_LABEL = "QUERY_SECRET"

# URL userinfo can carry credentials (``https://user:password@host`` or
# ``postgres://user:password@host``). Redact the whole userinfo component
# while preserving the scheme and host so the report still identifies the
# endpoint. A ``?``/``#`` cannot legally appear in userinfo unescaped, so
# excluding them prevents treating a query value that merely contains ``@``
# as userinfo.
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/@?#\s]+)@")
_URL_USERINFO_LABEL = "URL_USERINFO"

# Only markers this module generates are trusted as already-redacted. Any
# other marker-shaped text is attacker-controlled and must have its contents
# scrubbed: otherwise ``<redacted:sk-...>`` would bypass every rule below.
_MARKER = re.compile(r"<redacted:([A-Za-z0-9_.:-]+)>")
_TRUSTED_MARKER_LABELS = frozenset(
    KNOWN_SECRET_ENV_VARS + [label for label, _ in _PATTERN_RULES] + [_URL_USERINFO_LABEL, _QUERY_SECRET_LABEL]
)

_DEPTH_LIMIT = 64


def _redact_url_userinfo(text: str) -> str:
    """Redact credentials embedded in URL userinfo."""
    return _URL_USERINFO.sub(
        lambda match: f"{match.group(1)}<redacted:{_URL_USERINFO_LABEL}>@",
        text,
    )


def _redact_query_secrets(text: str) -> str:
    """Redact values of secret-like query parameters, keeping URLs readable."""
    result: list[str] = []
    cursor = 0
    for match in _QUERY_SECRET_VALUE.finditer(text):
        result.append(text[cursor : match.start(3)])
        result.append(f"<redacted:{_QUERY_SECRET_LABEL}>")
        cursor = match.end(3)
    result.append(text[cursor:])
    return "".join(result)


def _env_values() -> list[tuple[str, str]]:
    """Return (env_var, value) for every known var that is currently set."""
    return [(name, value) for name in KNOWN_SECRET_ENV_VARS if (value := os.environ.get(name))]


def _env_substitutions() -> list[tuple[re.Pattern[str], str]]:
    """Build substitution rules for environment values.

    Credential values at or above the minimum length are matched as substrings
    so embedding them in a longer token cannot hide them. Descriptive endpoint
    and deployment values keep token boundaries: an environment variable like
    ``AZURE_OPENAI_DEPLOYMENT=prod`` describes a deployment, not a credential,
    and matching ``prod`` inside ``production`` corrupts prose.
    """
    rules: list[tuple[int, re.Pattern[str], str]] = []
    for name, value in _env_values():
        candidate = value.strip()
        if len(candidate) < _MIN_ENV_VALUE_LEN:
            continue
        if name in _NON_CREDENTIAL_ENV_VARS and candidate.isalnum() and len(candidate) < _MIN_PLAIN_ENV_WORD_LEN:
            continue
        # Credential values are matched as substrings (after the minimum-length
        # filter) so repeated/adjacent copies cannot slip past. Descriptive
        # endpoint/deployment values retain boundary matching to protect prose.
        distinctive = (
            name not in _NON_CREDENTIAL_ENV_VARS or not candidate.isalnum() or len(candidate) >= _MIN_PLAIN_ENV_WORD_LEN
        )
        if distinctive:
            pattern = re.compile(re.escape(candidate))
        else:
            pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(candidate)}(?![A-Za-z0-9])")
        rules.append((len(candidate), pattern, f"<redacted:{name}>"))
    # Longest values first so overlapping values cannot fragment a longer
    # credential before it is redacted.
    rules.sort(key=lambda item: item[0], reverse=True)
    return [(pattern, replacement) for _, pattern, replacement in rules]


def _apply_outside_markers(text: str, transform: Callable[[str], str]) -> str:
    """Apply ``transform`` outside redaction markers generated by this module.

    An unknown marker-shaped label is not trusted as proof that its contents
    are safe. Its label is transformed instead; when that reveals a secret the
    scrubbed result replaces the forged marker rather than nesting inside it.
    """
    if not _MARKER.search(text):
        return transform(text)
    parts: list[str] = []
    cursor = 0
    for match in _MARKER.finditer(text):
        parts.append(transform(text[cursor : match.start()]))
        label = match.group(1)
        if label in _TRUSTED_MARKER_LABELS:
            parts.append(match.group(0))
        else:
            scrubbed_label = transform(label)
            parts.append(match.group(0) if scrubbed_label == label else scrubbed_label)
        cursor = match.end()
    parts.append(transform(text[cursor:]))
    return "".join(parts)


def _make_pattern_replacer(pattern: re.Pattern[str], replacement: str) -> Callable[[str], str]:
    """Return a one-arg callable that applies ``pattern.sub(replacement, chunk)``.

    Binding ``pattern`` and ``replacement`` as parameters (rather than closing
    over loop variables) avoids late-binding capture while keeping the returned
    callable strictly ``Callable[[str], str]``.
    """

    def _replace(chunk: str) -> str:
        return pattern.sub(replacement, chunk)

    return _replace


def _make_label_replacer(pattern: re.Pattern[str], label: str) -> Callable[[str], str]:
    """Return a one-arg callable that redacts a pattern match to a named marker."""

    def _replace(chunk: str) -> str:
        return pattern.sub(f"<redacted:{label}>", chunk)

    return _replace


def scrub(text: str) -> str:
    """Replace known secrets and evidential key patterns with redaction markers.

    Matching is case-sensitive for environment values. Credential values are
    matched wherever they occur once past the minimum length; descriptive
    endpoint/deployment values retain token boundaries. Repeated application
    is stable: redaction markers generated by this module are not rewritten.
    """
    rules = _env_substitutions()

    def transform(segment: str) -> str:
        out = segment
        for pattern, replacement in rules:
            out = _apply_outside_markers(out, _make_pattern_replacer(pattern, replacement))
        for label, pattern in _PATTERN_RULES:
            out = _apply_outside_markers(out, _make_label_replacer(pattern, label))
        return out

    # URL components are redacted on the re-joined text (not per marker-free
    # segment): an environment value may already have become a marker inside
    # the userinfo, and the whole credential still has to disappear.
    out = _apply_outside_markers(text, transform)
    out = _redact_url_userinfo(out)
    return _redact_query_secrets(out)


def scrub_message(text: str, limit: int = 240) -> str:
    """Scrub secrets from an exception message, then truncate it for storage."""
    return truncate(scrub(text), limit)


def _scrub_bytes(value: bytes | bytearray) -> str:
    """Project bytes to text safely; binary data never exposes its raw repr."""
    raw = bytes(value)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<binary:{len(raw)} bytes>"
    return scrub(decoded)


def _scrub_key(key: Any) -> Any:
    """Project a dictionary key to a safe, JSON-compatible value."""
    if isinstance(key, str):
        return scrub(key)
    if key is None or isinstance(key, (bool, int, float)):
        return key
    if isinstance(key, (bytes, bytearray)):
        return _scrub_bytes(key)
    if isinstance(key, pathlib.PurePath):
        return scrub(str(key))
    if isinstance(key, (_datetime.datetime, _datetime.date, _datetime.time)):
        return scrub(key.isoformat())
    # Arbitrary objects may render sensitive state in ``repr``; keep only the
    # type name so an unrecognised key cannot bypass redaction.
    return f"<unsupported-key:{type(key).__name__}>"


def _scrub_value(data: Any, depth: int) -> Any:
    """Recursively project an arbitrary value into a scrubbed, JSON-safe form."""
    if depth > _DEPTH_LIMIT:
        return "<unsupported:maximum-depth>"
    if isinstance(data, str):
        return scrub(data)
    if isinstance(data, (bytes, bytearray)):
        return _scrub_bytes(data)
    if isinstance(data, Mapping):
        return {_scrub_key(key): _scrub_value(value, depth + 1) for key, value in data.items()}
    if isinstance(data, (list, tuple)):
        return [_scrub_value(item, depth + 1) for item in data]
    if isinstance(data, (set, frozenset)):
        projected = [_scrub_value(item, depth + 1) for item in data]
        # Sets have no stable iteration order; sort so reports are deterministic.
        return sorted(projected, key=lambda item: (type(item).__name__, repr(item)))
    if isinstance(data, pathlib.PurePath):
        return scrub(str(data))
    if isinstance(data, (_datetime.datetime, _datetime.date, _datetime.time)):
        return scrub(data.isoformat())
    if data is None or isinstance(data, (bool, int, float)):
        return data
    # Do not call ``str()``/``repr()`` on arbitrary objects: a model or engine
    # integration may expose credentials or internal state that way.
    return f"<unsupported:{type(data).__name__}>"


def scrub_dict(data: Any) -> Any:
    """Recursively scrub every string, including dictionary keys, in a structure.

    The projection is JSON-compatible: tuples/sets become lists, bytes are
    decoded (or replaced with a length-only marker), path-like values become
    strings, and unsupported objects become a type-only placeholder. No
    unknown object's ``repr`` is emitted, so non-string engine results cannot
    bypass redaction.
    """
    return _scrub_value(data, 0)


__all__ = ["KNOWN_SECRET_ENV_VARS", "scrub", "scrub_dict", "scrub_message"]
