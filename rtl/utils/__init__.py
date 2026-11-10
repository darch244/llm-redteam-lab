"""Utility modules — filesystem safety, text heuristics, secret scrubbing."""

from __future__ import annotations

from rtl.utils.files import ensure_dir, load_yaml, write_json_atomic
from rtl.utils.secrets import scrub, scrub_dict, scrub_message
from rtl.utils.text import (
    contains_any,
    has_expected_evidence,
    looks_like_base64_blob,
    looks_like_key_value_lines,
    looks_like_parrot,
    parse_marker,
    slugify,
    truncate,
)

__all__ = [
    "contains_any",
    "ensure_dir",
    "has_expected_evidence",
    "load_yaml",
    "looks_like_base64_blob",
    "looks_like_key_value_lines",
    "looks_like_parrot",
    "parse_marker",
    "scrub",
    "scrub_dict",
    "scrub_message",
    "slugify",
    "truncate",
    "write_json_atomic",
]
