"""SARIF v2.1.0 reporter for CI/CD and GitHub Advanced Security integration."""

from __future__ import annotations

import json
import pathlib
from typing import TYPE_CHECKING, Any

from rtl.evaluation.atlas import ATLAS_MAP
from rtl.utils.files import atomic_write_text
from rtl.utils.secrets import scrub

if TYPE_CHECKING:
    from rtl.reporting.models import ScanResult

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(
    result: ScanResult,
    dest: str | pathlib.Path,
    *,
    redact: bool = True,
) -> pathlib.Path:
    """Generate a SARIF v2.1.0 JSON report."""
    target_path = pathlib.Path(dest)
    payload = generate_sarif_dict(result, redact=redact)
    content = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(target_path, content)
    return target_path


def generate_sarif_dict(result: ScanResult, *, redact: bool = True) -> dict[str, Any]:
    """Build a compliant SARIF v2.1.0 dictionary from a ScanResult."""
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    _scrub = scrub if redact else (lambda v: str(v))

    for finding in result.findings:
        if finding.skipped:
            continue

        atlas_id = finding.atlas_ids[0] if finding.atlas_ids else "AML.T0051"
        atlas_info = ATLAS_MAP.get(atlas_id, {})
        rule_name = atlas_info.get("name", finding.technique or atlas_id)

        if atlas_id not in rules_dict:
            rules_dict[atlas_id] = {
                "id": atlas_id,
                "name": rule_name.replace(" ", ""),
                "shortDescription": {"text": f"MITRE ATLAS {atlas_id}: {rule_name}"},
                "fullDescription": {"text": atlas_info.get("description", f"Adversarial technique {atlas_id}")},
                "helpUri": atlas_info.get("url", f"https://atlas.mitre.org/techniques/{atlas_id}"),
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")},
                "properties": {
                    "tags": ["security", "ai-safety", "llm-redteam", atlas_id],
                    "tactic": atlas_info.get("tactic", "Execution"),
                },
            }

        level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")

        message_text = (
            f"Adversarial probe {finding.attack_id} ('{finding.name}') against "
            f"{result.meta.provider}:{result.meta.model} landed with verdict '{finding.verdict_label}'. "
            f"Severity: {finding.severity.upper()} (score {finding.severity_score}/4)."
        )

        if finding.scenario:
            location_uri = f"scenarios/{finding.scenario}.yaml"
        else:
            location_uri = f"probes/{finding.category}/{finding.attack_id}.yaml"

        sarif_results.append(
            {
                "ruleId": atlas_id,
                "level": level,
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "attackId": finding.attack_id,
                    "category": finding.category,
                    "technique": finding.technique,
                    "confidence": finding.confidence,
                    "severity": finding.severity,
                    "rationale": finding.rationale,
                    "responseExcerpt": _scrub(finding.response[:300]),
                },
            }
        )

    sarif_run = {
        "tool": {
            "driver": {
                "name": result.meta.tool,
                "version": result.meta.version or "0.1.0",
                "informationUri": "https://github.com/darch244/llm-redteam-lab",
                "rules": list(rules_dict.values()),
            }
        },
        "results": sarif_results,
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [sarif_run],
    }


__all__ = ["generate_sarif_dict", "render_sarif"]
