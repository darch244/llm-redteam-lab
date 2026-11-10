"""Scan orchestrator — glues targets, probes, judge and reporters.

``run_scan`` is the heart of every ``rtl scan`` invocation. It is
deliberately async so we can ``await target.asend()`` and schedule
multiple probes concurrently in future versions.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from rtl.attacks.loader import resolve as resolve_probes
from rtl.config import ScanOptions
from rtl.engines import EngineUnavailableError, build_engine
from rtl.evaluation.judge import Judge, JudgeVerdict
from rtl.evaluation.severity import SeverityResult
from rtl.evaluation.severity import score as severity_score
from rtl.evaluation.verdict_policy import VerdictPolicy
from rtl.logging import get_logger
from rtl.reporting.html_reporter import render_html
from rtl.reporting.json_reporter import write_json
from rtl.reporting.markdown_reporter import render_markdown
from rtl.reporting.models import Finding, ProbeResult, ReportMeta, ScanResult
from rtl.reporting.sarif_reporter import render_sarif
from rtl.scenarios import SCENARIOS, ScenarioError, ScenarioUnsupported
from rtl.utils.files import ensure_dir
from rtl.utils.secrets import scrub, scrub_dict, scrub_message

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
    target = options.target_override if options.target_override is not None else options.target.build_target()
    target_fp = target.fingerprint()
    log.info("target: %s:%s", target.provider, target.model)

    notes: list[str] = []
    # Stage 0 ships the adaptive/seed/budget options and the integration point,
    # but not the planner, ledger or replay system. Be explicit instead of
    # silently ignoring an opt-in or pretending a budget was enforced.
    if options.adaptive and not options.planner:
        log.warning("adaptive planning requested but not implemented in this build; running the static probe loop")
        notes.append("adaptive planning requested but not implemented in this build; the static probe loop was used")
    if options.seed is not None and not options.planner:
        log.info("deterministic seed: %d (accepted; the static loop consumes no randomness)", options.seed)
    if options.budget is not None and not options.planner:
        log.warning("budget configuration supplied but budget enforcement is not implemented in this build")
        notes.append("budget configuration supplied but not enforced in this build")

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
    verdict_policy = VerdictPolicy(judge)

    findings: list[Finding] = []
    adaptive_payload: dict[str, Any] | None = None

    if options.planner in ("heuristic", "adaptive", "static", "ev_adaptive"):
        from rtl.planning.engine import AdaptiveEngine

        engine_opts = options.model_copy(
            update={"adaptive": options.planner in ("heuristic", "adaptive", "ev_adaptive")}
        )
        engine = AdaptiveEngine(engine_opts, target, probes, verdict_policy)
        findings, plan_state, manifest = await engine.run()
        adaptive_payload = {
            "plan_state": plan_state.model_dump(mode="json"),
            "manifest": manifest.model_dump(mode="json"),
            "evidence_graph": engine.evidence_graph.model_dump(mode="json"),
        }
        notes.append(f"adaptive planner '{options.planner}' completed with {len(findings)} findings")
    else:
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
                # scrub + truncate before persisting: exception text may contain
                # API keys, tokens or secret-bearing URLs from the transport layer
                error_text = scrub_message(f"{type(exc).__name__}: {exc}")
                log.error("probe %s failed: %s", attack.attack_id, error_text)
                severity = SeverityResult(
                    level="info",
                    score=0,
                    blocked=False,
                    rationale=[f"probe did not complete — target error: {error_text}"],
                )
                verdict = JudgeVerdict(
                    label="ambiguous",
                    success=False,
                    confidence=0.0,
                    reason="probe did not complete; target raised an exception",
                    source="heuristic",
                    outcome="failed",
                )
                probe_result = ProbeResult(
                    probe=attack,
                    response="",
                    error=error_text,
                    effective_prompt=effective_prompt,
                    raw={
                        "verdict": verdict.to_dict(),
                        "severity": severity.to_dict(),
                        "error_class": type(exc).__name__,
                        "expected": list(attack.expected),
                        "evidence_hit": False,
                    },
                    elapsed_seconds=time.monotonic() - t0,
                )
                findings.append(probe_result.to_finding(verdict, severity, target_fp))
                continue

            expected = list(attack.expected)
            probe_result = ProbeResult(
                probe=attack,
                response=response,
                effective_prompt=effective_prompt,
                raw={},
                elapsed_seconds=elapsed,
            )
            try:
                verdict = verdict_policy.evaluate(probe_result, prompt=prompt)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the response is already captured — never drop the probe
                judge_error = scrub_message(f"{type(exc).__name__}: {exc}")
                log.error("judge failed for %s: %s", attack.attack_id, judge_error)
                verdict = JudgeVerdict(
                    label="ambiguous",
                    success=False,
                    confidence=0.0,
                    reason=f"judge layer failed; deterministic result unavailable ({judge_error})",
                    source="heuristic",
                    outcome="suspected",
                )
            severity = severity_score(attack, verdict)
            probe_result.raw = {
                "verdict": verdict.to_dict(),
                "severity": severity.to_dict(),
                "expected": expected,
                "evidence_hit": verdict.evidence_hit,
            }
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
            notes=notes,
        ),
        findings=findings,
        engine_results=engine_results,
        scenario_outcomes=scenario_outcomes,
        adaptive=adaptive_payload,
    )
    scan_result.aggregate()

    if not dry:
        report_dir = ensure_dir(options.output_dir)
        json_path = write_json(scan_result, report_dir / "report.json", redact=options.redact)
        html_path = render_html(scan_result, report_dir / "report.html", redact=options.redact)
        sarif_path = render_sarif(scan_result, report_dir / "report.sarif", redact=options.redact)
        md_path = render_markdown(scan_result, report_dir / "report.md", redact=options.redact)
        log.info("reports written to %s", report_dir)
        log.info("  JSON: %s", json_path)
        log.info("  HTML: %s", html_path)
        log.info("  SARIF: %s", sarif_path)
        log.info("  Markdown: %s", md_path)

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
            error_text = scrub_message(str(exc))
            log.warning("scenario %s unsupported: %s", name, error_text)
            outcomes.append(
                {
                    "scenario": name,
                    "status": "unsupported",
                    "stage": "runner",
                    "error": error_text,
                }
            )
            continue
        except ScenarioError as exc:
            error_text = scrub_message(str(exc))
            log.error("scenario %s failed: %s", name, error_text)
            outcomes.append(
                {
                    "scenario": name,
                    "status": "error",
                    "stage": "runner",
                    "error": error_text,
                }
            )
            continue
        except Exception as exc:  # target/storage errors must not abort the scan
            error_text = scrub_message(f"{type(exc).__name__}: {exc}")
            log.error("scenario %s errored: %s", name, error_text)
            outcomes.append(
                {
                    "scenario": name,
                    "status": "error",
                    "stage": "runner",
                    "error": error_text,
                }
            )
            continue

        for pr in results:
            context = _scenario_probe_context(pr)
            if pr.skipped:
                outcomes.append(
                    {
                        "scenario": name,
                        "status": "skipped",
                        **context,
                        "error": scrub_message(pr.error) if pr.error else None,
                    }
                )
                continue
            try:
                verdict = judge.evaluate(
                    pr.probe.prompt,
                    pr.response,
                    pr.probe.category,
                    expected=list(pr.probe.expected) or None,
                    scenario=name,
                    canary=pr.probe.canary,
                    raw=pr.raw,
                    probe_result=pr,
                )
                severity = severity_score(pr.probe, verdict, scenario=name)
                finding = pr.to_finding(verdict, severity, target_fp, scenario=name)
                entry = finding.model_dump(mode="json")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # never drop already-captured scenario evidence
                error_text = scrub_message(f"{type(exc).__name__}: {exc}")
                log.error(
                    "scenario %s/%s evaluation failed: %s",
                    name,
                    pr.probe.attack_id,
                    error_text,
                )
                outcomes.append(
                    {
                        "scenario": name,
                        "status": "error",
                        "outcome": "suspected",
                        **context,
                        "error": error_text,
                        "response": scrub(pr.response),
                        "raw": scrub_dict(pr.raw),
                        "expected": list(pr.probe.expected),
                        "evidence_hit": None,
                    }
                )
                continue
            entry["scenario"] = name
            entry["raw"] = dict(entry.get("raw") or {})
            entry["raw"]["expected"] = list(pr.probe.expected)
            entry["raw"]["evidence_hit"] = verdict.evidence_hit
            outcomes.append(entry)
            log.info(
                "scenario %s: %s -> %s (severity %s)",
                name,
                pr.probe.attack_id,
                verdict.label,
                severity.level,
            )
    return outcomes


def _scenario_probe_context(pr: ProbeResult) -> dict[str, Any]:
    """Identity/context preserved on skipped or failed scenario evaluations."""
    return {
        "probe_id": pr.probe.attack_id,
        "name": pr.probe.name,
        "category": pr.probe.category,
        "technique": pr.probe.technique,
        "prompt": scrub(pr.probe.prompt),
        "atlas_ids": [pr.probe.atlas_id],
        "expected": list(pr.probe.expected),
        "elapsed_seconds": pr.elapsed_seconds,
    }


def _version() -> str:
    from rtl._version import __version__

    return __version__


__all__ = ["run_scan"]
