"""Scan orchestrator — glues targets, probes, judge and reporters.

``run_scan`` is the heart of every ``rtl scan`` invocation. It is
deliberately async so we can ``await target.asend()`` and schedule
multiple probes concurrently in future versions.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from rtl.attacks.loader import resolve as resolve_probes
from rtl.config import ScanOptions
from rtl.engines import EngineUnavailableError, build_engine
from rtl.evaluation.judge import Judge, JudgeVerdict
from rtl.evaluation.severity import SeverityResult
from rtl.evaluation.severity import score as severity_score
from rtl.logging import get_logger
from rtl.reporting.html_reporter import render_html
from rtl.reporting.json_reporter import write_json
from rtl.reporting.models import Finding, ProbeResult, ReportMeta, ScanResult
from rtl.scenarios import SCENARIOS, ScenarioError, ScenarioUnsupported
from rtl.utils.files import ensure_dir

if TYPE_CHECKING:
    from rtl.attacks.model import AttackPrompt

log = get_logger("runner")


def _execution_error_finding(
    attack: AttackPrompt,
    effective_prompt: str | None,
    target_fp: dict[str, Any],
    exc: Exception,
) -> Finding:
    """Project a probe execution failure into an explicit error finding.

    The probe is recorded rather than silently dropped, and is deliberately
    flagged ``skipped`` with the exception message attached so it is never
    misclassified as a successful attack, a refusal or a guarded outcome. It is
    excluded from every security-outcome tally by :meth:`ScanResult.aggregate`.
    """
    verdict = JudgeVerdict(
        label="ambiguous",
        success=False,
        confidence=0.0,
        reason=f"execution error — probe did not complete: {exc}",
        source="heuristic",
    )
    severity = SeverityResult(
        level="info",
        score=0,
        blocked=False,
        rationale=["execution error — no security conclusion drawn"],
    )
    result = ProbeResult(
        probe=attack,
        response="",
        effective_prompt=effective_prompt,
        error=str(exc),
        skipped=True,
    )
    return result.to_finding(verdict, severity, target_fp)


async def run_scan(options: ScanOptions, *, dry: bool = False) -> ScanResult:
    """Execute a full scan and write reports.

    Args:
        options: Fully-resolved scan options (target, suite, judge, etc.).
        dry: If true, send all probes without writing report files.
    """
    t_start = time.monotonic()
    target = options.target.build_target()
    target_fp = target.fingerprint()
    log.info("target: %s:%s", target.provider, target.model)

    probes = resolve_probes(
        categories=options.suite.effective_categories(),
        attack_ids=options.suite.attack_ids,
        max_per_category=options.suite.max_per_category,
    )
    log.info("probes resolved: %d", len(probes))

    judge_target = None
    # `offline` forces the deterministic heuristic judge: no judge model is
    # constructed and no external engine is invoked, so a scan needs no network.
    judge_mode = "heuristic" if options.offline else options.judge.mode
    if not options.offline and options.judge.mode in ("auto", "llm") and options.judge.model:
        from rtl.config import TargetConfig

        judge_target = TargetConfig.parse(options.judge.model).build_target()
    judge = Judge(judge_target=judge_target, mode=judge_mode)

    findings: list[Finding] = []
    for i, attack in enumerate(probes, 1):
        prompt = attack.prompt
        effective_prompt: str | None = None
        if options.max_prompt_len and len(prompt) > options.max_prompt_len:
            prompt = prompt[: options.max_prompt_len]
            # Remember exactly what the target received so the report's
            # reproduction data stays faithful to the truncated prompt.
            effective_prompt = prompt
        log.info("probe %d/%d %s", i, len(probes), attack.attack_id)
        elapsed = 0.0
        response = ""
        try:
            t0 = time.monotonic()
            response = await target.asend(prompt)
            elapsed = time.monotonic() - t0
        except Exception as exc:
            log.error("probe %s failed: %s", attack.attack_id, exc)
            findings.append(_execution_error_finding(attack, effective_prompt, target_fp, exc))
            continue

        verdict = judge.evaluate(prompt, response, attack.category, canary=attack.canary)
        severity = severity_score(attack, verdict)
        probe_result = ProbeResult(
            probe=attack,
            response=response,
            effective_prompt=effective_prompt,
            raw={"verdict": verdict.to_dict(), "severity": severity.to_dict()},
            elapsed_seconds=elapsed,
        )
        findings.append(probe_result.to_finding(verdict, severity, target_fp))
        log.info(
            "  %s -> %s (conf %.2f, severity %s)",
            attack.attack_id,
            verdict.label,
            verdict.confidence,
            severity.level,
        )

    scenario_outcomes: list[dict[str, Any]] = await _run_scenarios(options, target, judge, target_fp)
    engine_results = _run_engines(options, [attack.prompt for attack in probes])
    scan_result = ScanResult(
        meta=ReportMeta(
            version=_version(),
            target_spec=options.target.kind + ":" + options.target.model,
            provider=target_fp.get("provider", target.provider),
            model=target_fp.get("model", target.model),
            base_url=target_fp.get("base_url"),
            suite=options.suite.name,
            suite_description=options.suite.description,
            judge_mode=judge_mode,
            duration_seconds=time.monotonic() - t_start,
        ),
        findings=findings,
        engine_results=engine_results,
        scenario_outcomes=scenario_outcomes,
    )
    scan_result.aggregate()

    if not dry:
        report_dir = ensure_dir(options.output_dir)
        json_path = write_json(scan_result, report_dir / "report.json", redact=options.redact)
        html_path = render_html(scan_result, report_dir / "report.html", redact=options.redact)
        log.info("reports written to %s", report_dir)
        log.info("  JSON: %s", json_path)
        log.info("  HTML: %s", html_path)

    return scan_result


def _run_engines(options: ScanOptions, prompts: list[str]) -> list[dict[str, Any]]:
    """Run the external engines named by the suite, recording the outcome.

    Engines are optional and often absent (garak/pyrit not installed). Rather
    than silently ignoring a suite's ``engines:`` list — which would make a
    suite like ``full.yaml`` *look* like it exercised those tools — every
    requested engine contributes exactly one entry describing whether it ran,
    was unavailable, or failed. These entries are metadata, never security
    findings, so they never affect the verdict tallies.
    """
    entries: list[dict[str, Any]] = []
    for name in options.suite.engines or ():
        if options.offline:
            entries.append(
                {
                    "engine": name,
                    "status": "skipped",
                    "detail": "offline mode — external engines are not run",
                }
            )
            continue
        try:
            engine = build_engine(name)
            results = engine.run(prompts)
        except EngineUnavailableError as exc:
            log.warning("engine %s unavailable: %s", name, exc.hint)
            entries.append({"engine": name, "status": "unavailable", "detail": exc.hint})
        except Exception as exc:  # engine boundaries are untrusted; never crash a scan
            log.error("engine %s failed: %s", name, exc)
            entries.append({"engine": name, "status": "error", "detail": str(exc)})
        else:
            log.info("engine %s produced %d result(s)", name, len(results))
            entries.append(
                {
                    "engine": name,
                    "status": "ok",
                    "detail": f"{len(results)} result(s)",
                    "results": [r.model_dump(mode="json") for r in results],
                }
            )
    return entries


async def _run_scenarios(
    options: ScanOptions,
    target: Any,
    judge: Judge,
    target_fp: dict[str, Any],
) -> list[dict[str, Any]]:
    """Execute every scenario named in the suite and judge its results."""
    outcomes: list[dict[str, Any]] = []
    for name in options.suite.scenarios or ():
        run_fn = SCENARIOS.get(name)
        if run_fn is None:
            raise ScenarioError(f"unknown scenario {name!r}; available: {', '.join(SCENARIOS)}")
        try:
            results = await run_fn(target, config=options.suite.scenario_configs.get(name, {}))
        except ScenarioUnsupported as exc:
            log.warning("scenario %s unsupported: %s", name, exc)
            outcomes.append({"scenario": name, "status": "unsupported", "error": str(exc)})
            continue
        except ScenarioError as exc:
            log.error("scenario %s failed: %s", name, exc)
            outcomes.append({"scenario": name, "status": "error", "error": str(exc)})
            continue

        for pr in results:
            if pr.skipped:
                outcomes.append(
                    {
                        "scenario": name,
                        "status": "skipped",
                        "probe_id": pr.probe.attack_id,
                        "error": pr.error,
                    }
                )
                continue
            verdict = judge.evaluate(pr.probe.prompt, pr.response, pr.probe.category, canary=pr.probe.canary)
            severity = severity_score(pr.probe, verdict, scenario=name)
            finding = pr.to_finding(verdict, severity, target_fp, scenario=name)
            entry = finding.model_dump(mode="json")
            entry["scenario"] = name
            outcomes.append(entry)
            log.info(
                "scenario %s: %s -> %s (severity %s)",
                name,
                pr.probe.attack_id,
                verdict.label,
                severity.level,
            )
    return outcomes


def _version() -> str:
    from rtl._version import __version__

    return __version__


__all__ = ["run_scan"]
