"""garak engine — an optional wrapper around Nvidia's garak gauntlet.

garak (https://github.com/NVIDIA/garak) ships hundreds of LLM vulnerability
probes (prompt injection, jailbreak, encoding attacks, leakrepetition,
...). Rather than reimplementing them, this engine shells out to the
installed ``garak`` CLI and maps per-probe results onto MITRE ATLAS.

Install with: ``pip install garak`` (or ``pip install llm-redteam-lab[garak]``).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any

from rtl.engines.base import Engine, EngineResult, EngineUnavailableError
from rtl.logging import get_logger

log = get_logger("garak")

# Common garak probes worth starting with. Full list: `garak --list_probes`.
DEFAULT_PROBES = [
    "promptinject",
    "jailbreak",
    "leakrepetition",
    "encoding.DanGeneration",
]

_ATLAS_BY_PROBE_PREFIX: dict[str, list[str]] = {
    "promptinject": ["AML.T0051.000"],
    "jailbreak": ["AML.T0054"],
    "encoding": ["AML.T0051", "AML.T0054"],
}


class GarakEngine(Engine):
    """Runs the external garak CLI from within an ``rtl`` scan."""

    name = "garak"
    description = "Nvidia's LLM vulnerability garak (external probes)"
    homepage = "https://github.com/NVIDIA/garak"

    def __init__(self, garak_bin: str | None = None) -> None:
        self.garak_bin = garak_bin or shutil.which("garak") or "garak"

    def run(
        self,
        prompts: list[str],
        *,
        model_type: str = "gpt",
        model_name: str | None = None,
        probes: list[str] | None = None,
        report_prefix: str | None = None,
        **_: Any,
    ) -> list[EngineResult]:
        """Execute garak against the configured model.

        Args:
            prompts: Ignored placeholder for interface compatibility — garak
                drives its own probes and generators.
            model_type: garak model classifier (``gpt``, ``huggingface``, ...).
            model_name: Model identifier garak should target (e.g. the env
                var name garak should read, such as ``env_var`` names).
            probes: Specific garak probe plugin names.
            report_prefix: garak report filename prefix.
        """
        if not shutil.which(self.garak_bin):
            raise EngineUnavailableError(
                self.name,
                "garak is not installed; run `pip install garak` (extra: `[garak]`)",
            )

        selected = probes or DEFAULT_PROBES
        cmd = [self.garak_bin, "--model_type", model_type, "--probes", ",".join(selected)]
        if model_name:
            cmd += ["--model_name", model_name]
        if report_prefix:
            cmd += ["--report_prefix", report_prefix]
        log.info("garak: running %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if proc.returncode != 0:
            log.warning("garak exited %d: %s", proc.returncode, proc.stderr[-400:])

        results: list[EngineResult] = []
        for prefix, found in self._load_report(report_prefix):
            for probe_id, attempts in found.items():
                success = any(item.get("passed", False) or item.get("status") == "fail" for item in attempts)
                results.append(
                    EngineResult(
                        engine=self.name,
                        probe_id=probe_id,
                        prompt=(probes[0] if probes else "") or prefix,
                        response=probe_id,
                        success=bool(success),
                        atlas_ids=self._atlas_for(probe_id),
                        summary=f"garak probe {probe_id} over {len(attempts)} attempts",
                        raw={"garak_prefix": prefix, "attempts": len(attempts)},
                    )
                )
        return results

    @staticmethod
    def _atlas_for(probe_id: str) -> list[str]:
        for prefix, ids in _ATLAS_BY_PROBE_PREFIX.items():
            if probe_id.startswith(prefix):
                return ids
        return ["AML.T0051"]

    @staticmethod
    def _load_report(report_prefix: str | None) -> list[tuple[str, dict[str, list[dict[str, Any]]]]]:
        """Best-effort parse of garak's JSON report files."""
        if not report_prefix:
            return []
        data: list[tuple[str, dict[str, list[dict[str, Any]]]]] = []
        try:
            with open(f"{report_prefix}.report.json", encoding="utf-8") as handle:
                report = json.load(handle)
            for plugin, entries in report.get("plugins", {}).items():
                attempts = entries.get("attempts", [])
                data.append((plugin, {plugin: attempts}))
        except (OSError, json.JSONDecodeError) as exc:
            logging.getLogger("rtl.garak").warning("could not parse garak report: %s", exc)
        return data


__all__ = ["DEFAULT_PROBES", "GarakEngine"]
