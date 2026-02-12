"""Filesystem helpers: safe paths, atomic JSON writes, YAML loading."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
from typing import Any

import yaml


def ensure_dir(path: str | pathlib.Path) -> pathlib.Path:
    """Create (and return) a directory, recursing as needed."""
    resolved = pathlib.Path(path).expanduser()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def write_json_atomic(path: str | pathlib.Path, data: Any, *, indent: int = 2) -> pathlib.Path:
    """Write JSON atomically (temp file + rename) to avoid torn reports."""
    dest = pathlib.Path(path)
    ensure_dir(dest.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=indent, default=str)
            handle.write("\n")
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return dest


def load_yaml(path: str | pathlib.Path) -> dict[str, Any]:
    """Load a YAML mapping, raising a helpful error on malformed input."""
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the root")
    return data


__all__ = ["ensure_dir", "load_yaml", "write_json_atomic"]
