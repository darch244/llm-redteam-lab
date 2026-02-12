"""JSON report writer/reader.

JSON reports are the machine-readable source of truth; HTML/PDF are derived
projections. Secrets are scrubbed before serialization when requested.
"""

from __future__ import annotations

import pathlib

from rtl.reporting.models import ScanResult
from rtl.utils.files import write_json_atomic
from rtl.utils.secrets import scrub_dict


def write_json(
    result: ScanResult,
    path: str | pathlib.Path,
    *,
    redact: bool = True,
) -> pathlib.Path:
    """Serialize a scan to JSON (atomic write)."""
    payload = result.model_dump(mode="json")
    if redact:
        payload = scrub_dict(payload)
    return write_json_atomic(path, payload)


def load_json(path: str | pathlib.Path) -> ScanResult:
    """Deserialize a scan JSON file back into a :class:`ScanResult`."""
    import json

    raw = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return ScanResult.model_validate(raw)


__all__ = ["load_json", "write_json"]
