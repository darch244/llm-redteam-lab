"""CLI entry point — the ``rtl`` command.

Commands:
    scan              Run a test suite against a target and produce reports
    list-suites       List bundled suite files
    list-attacks      Count/list attack probes by category
    report            Regenerate HTML/JSON reports from an existing report.json
    target            Show a parsed target configuration (dry run)
    version           Print the installed version
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import time
from typing import TYPE_CHECKING, Any, Literal, cast

import typer
from rich.console import Console
from rich.table import Table

from rtl.config import JudgeConfig, Suite, TargetConfig, list_suites
from rtl.logging import setup_logging

if TYPE_CHECKING:
    from rtl.config import ScanOptions
    from rtl.reporting.models import ScanResult

app = typer.Typer(
    name="rtl",
    help="LLM Red Team Lab — adversarial testing framework for LLM applications.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console(stderr=True)


@app.command()
def scan(
    target: str = typer.Option(..., help="Target spec, e.g. ollama:llama3.1 or mock"),
    suite: str | None = typer.Option(None, help="Path to suite YAML (default: quick)"),
    categories: list[str] | None = typer.Option(None, help="Only these categories"),
    attack_ids: list[str] | None = typer.Option(None, help="Only these probe IDs"),
    judge_model: str | None = typer.Option(None, help="Judge model spec, e.g. ollama:mistral"),
    judge_mode: str = typer.Option("auto", help="heuristic / llm / auto"),
    output: str = typer.Option("reports", help="Output directory"),
    offline: bool = typer.Option(False, help="Skip LLM judge and engines"),
    max_prompt_len: int | None = typer.Option(None, help="Truncate long prompts"),
    adaptive: bool = typer.Option(
        False,
        help="Request adaptive planning (not implemented yet; static loop with an explicit warning)",
    ),
    planner: str | None = typer.Option(None, help="Adaptive attack planner: heuristic / static"),
    seed: int | None = typer.Option(None, help="Deterministic seed for future adaptive planning/replay"),
    budget_probes: int | None = typer.Option(None, "--budget-probes", help="Probe execution budget limit"),
    budget_turns: int | None = typer.Option(None, "--budget-turns", help="Interaction turn budget limit"),
    budget_seconds: float | None = typer.Option(None, "--budget-seconds", help="Time budget limit in seconds"),
    system_prompt: str | None = typer.Option(None, help="Custom system prompt to configure target with"),
    system_prompt_file: str | None = typer.Option(None, help="Path to text file containing system prompt"),
    redact: bool = typer.Option(True, help="Scrub secrets in reports"),
    log_level: str = typer.Option("INFO", help="Log verbosity"),
    json_logs: bool = typer.Option(False, "--json-logs", help="Emit newline-delimited JSON logs"),
) -> None:
    """Run an attack suite against a target and produce JSON + HTML reports."""
    setup_logging(log_level, json_mode=json_logs)
    target_cfg = TargetConfig.parse(target)
    effective_sys = system_prompt
    if system_prompt_file:
        p_file = pathlib.Path(system_prompt_file)
        if not p_file.is_file():
            console.print(f"[red]System prompt file not found: {p_file}[/red]")
            raise typer.Exit(1)
        effective_sys = p_file.read_text(encoding="utf-8")
    if effective_sys:
        target_cfg = target_cfg.model_copy(update={"system_prompt": effective_sys})
    suite_path = str(_find_suite(suite or "quick.yaml"))
    suite_cfg = Suite.load(suite_path)
    if categories:
        suite_cfg = suite_cfg.model_copy(update={"categories": list(categories)})
    if attack_ids:
        suite_cfg = suite_cfg.model_copy(update={"attack_ids": list(attack_ids), "categories": []})
    if judge_mode not in ("auto", "llm", "heuristic"):
        console.print(f"[red]Invalid judge_mode '{judge_mode}'; must be one of: auto, llm, heuristic[/red]")
        raise typer.Exit(2)
    judge_cfg = JudgeConfig(
        mode=cast(Literal["auto", "llm", "heuristic"], judge_mode),
        model=judge_model,
    )
    from rtl.config import BudgetLimits, ScanOptions

    scan_budget = None
    if budget_probes is not None or budget_turns is not None or budget_seconds is not None:
        scan_budget = BudgetLimits(
            max_probes=budget_probes if budget_probes is not None else 100,
            max_turns=budget_turns if budget_turns is not None else 100,
            max_seconds=budget_seconds if budget_seconds is not None else 3600.0,
        )

    options = ScanOptions(
        target=target_cfg,
        suite=suite_cfg,
        judge=judge_cfg,
        output_dir=pathlib.Path(output),
        offline=offline,
        redact=redact,
        max_prompt_len=max_prompt_len,
        adaptive=adaptive,
        planner=cast(Any, planner),
        budget=scan_budget,
        seed=seed,
    )
    result = asyncio.run(_run(options))
    console.print(
        f"[green]Scan complete:[/green] {result.summary.total} probes, "
        f"{result.summary.succeeded} succeeded, "
        f"{result.summary.refused} refused, "
        f"{result.summary.blocked} guarded, "
        f"{result.summary.ambiguous} ambiguous"
    )
    console.print(f"[cyan]Reports:[/cyan] {options.output_dir}")


async def _run(options: ScanOptions) -> ScanResult:
    from rtl.runner import run_scan

    return await run_scan(options)


@app.command("list-suites")
def list_suites_cmd() -> None:
    """List bundled YAML test-suite files."""
    table = Table(title="Bundled suites", show_lines=False)
    table.add_column("File", style="cyan")
    table.add_column("Suite name", style="bold")
    table.add_column("Categories", style="dim")
    for path in list_suites():
        try:
            s = Suite.load(path)
            cats = ", ".join(s.effective_categories() or ["all"])
            table.add_row(path.name, s.name, cats)
        except Exception:  # pragma: no cover
            table.add_row(path.name, "(parse error)", "")
    console.print(table)


@app.command("list-attacks")
def list_attacks_cmd() -> None:
    """Show the attack prompt library by category."""
    from rtl.attacks.loader import CATEGORIES, category_stats, load_cache

    table = Table(title="Attack prompt library", show_lines=False)
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Atlas", style="dim")
    stats = category_stats()
    cache = load_cache()
    for cat in CATEGORIES:
        probes = cache[cat]
        atlas_ids = sorted(set(p.atlas_id for p in probes))
        table.add_row(cat, str(stats[cat]), ", ".join(atlas_ids[:3]) + ("..." if len(atlas_ids) > 3 else ""))
    table.add_row("[bold]TOTAL[/bold]", str(sum(stats.values())), "—")
    console.print(table)
    console.print(
        "[dim]Original probes: " + str(sum(1 for ps in cache.values() for p in ps if p.source == "original")) + "[/dim]"
    )


@app.command("report")
def report_cmd(
    input_file: str = typer.Option(..., help="Path to report.json"),
    output: str = typer.Option(None, help="Output path (default: <input>.<format>)"),
    format: str = typer.Option("html", help="html / json / pdf / sarif / markdown"),
    redact: bool = typer.Option(True, help="Scrub secrets when regenerating"),
) -> None:
    """Regenerate HTML/PDF/SARIF/Markdown from an existing report.json."""
    from rtl.reporting.json_reporter import load_json

    result = load_json(input_file)
    suffix = ".md" if format in ("markdown", "md") else f".{format}"
    dest = pathlib.Path(output) if output else pathlib.Path(input_file).with_suffix(suffix)
    if format == "json":
        from rtl.reporting.json_reporter import write_json

        write_json(result, dest, redact=redact)
    elif format == "pdf":
        from rtl.reporting.pdf_reporter import render_pdf

        render_pdf(result, dest)
    elif format == "sarif":
        from rtl.reporting.sarif_reporter import render_sarif

        render_sarif(result, dest, redact=redact)
    elif format in ("markdown", "md"):
        from rtl.reporting.markdown_reporter import render_markdown

        render_markdown(result, dest, redact=redact)
    else:
        from rtl.reporting.html_reporter import render_html

        render_html(result, dest, redact=redact)
    console.print(f"[green]Report written:[/green] {dest}")


@app.command("target")
def target_cmd(
    spec: str | None = typer.Argument(None, help="Target spec, e.g. ollama:llama3.1"),
    list: bool = typer.Option(False, "--list", "-l", help="Show all supported providers"),
) -> None:
    """Inspect a target spec or list supported providers."""
    if list:
        table = Table(title="Supported providers")
        table.add_column("Provider", style="cyan")
        table.add_column("Default model", style="bold")
        for provider, model in sorted(_provider_defaults().items()):
            table.add_row(provider, model)
        console.print(table)
        return
    if not spec:
        console.print("[red]Provide a target spec or use --list[/red]")
        raise typer.Exit(1)
    cfg = TargetConfig.parse(spec)
    fp = cfg.build_target().fingerprint()
    console.print("[bold]Target config[/bold]")
    for k, v in fp.items():
        console.print(f"  {k}: {v}")


@app.command("replay")
def replay_cmd(
    manifest_file: str = typer.Option(..., "--manifest", "-m", help="Path to manifest.json or report.json"),
    output: str = typer.Option("reports/replay", help="Output directory for replayed reports"),
    max_probes: int | None = typer.Option(
        None, "--max-probes", help="Maximum probes to replay (enforces replay budget limit)"
    ),
) -> None:
    """Deterministically replay a recorded scan manifest offline with optional budget enforcement."""
    import json

    from rtl.config import ScanOptions
    from rtl.planning.models import ReplayManifest
    from rtl.planning.replay import ReplayTarget

    path = pathlib.Path(manifest_file)
    if not path.is_file():
        console.print(f"[red]Manifest file not found: {path}[/red]")
        raise typer.Exit(1)

    raw_data = json.loads(path.read_text(encoding="utf-8"))
    manifest_data = raw_data
    if "adaptive" in raw_data and isinstance(raw_data["adaptive"], dict) and "manifest" in raw_data["adaptive"]:
        manifest_data = raw_data["adaptive"]["manifest"]

    manifest = ReplayManifest.model_validate(manifest_data)

    # Budget enforcement in replay: bound replayed events to max_probes if requested or configured
    effective_max = max_probes if max_probes is not None else (manifest.limits.max_probes if manifest.limits else None)
    if effective_max is not None and effective_max > 0 and len(manifest.events) > effective_max:
        console.print(
            f"[yellow]Enforcing replay probe budget:[/yellow] bounding replay to {effective_max} probes "
            f"(manifest has {len(manifest.events)})"
        )
        bounded_events = manifest.events[:effective_max]
        manifest = manifest.model_copy(update={"events": bounded_events})

    console.print(
        f"[bold cyan]Replaying scan:[/bold cyan] {len(manifest.events)} events recorded with seed {manifest.seed}"
    )

    replay_target = ReplayTarget(manifest)
    suite_name = manifest.suite_name
    suite_file = _find_suite(f"{suite_name}.yaml") if not suite_name.endswith(".yaml") else _find_suite(suite_name)
    suite_cfg = Suite.load(suite_file)
    # Replay probes recorded in manifest without running extra unrecorded scenarios
    recorded_probe_ids = [e.probe_id for e in manifest.events]
    suite_cfg = suite_cfg.model_copy(
        update={
            "attack_ids": recorded_probe_ids,
            "categories": [],
            "scenarios": [],
            "engines": [],
        }
    )
    target_cfg = TargetConfig(kind="mock", model=manifest.target_fingerprint.get("model", "replay-model"))
    judge_cfg = JudgeConfig(mode=cast(Literal["auto", "llm", "heuristic"], manifest.judge_mode))

    options = ScanOptions(
        target=target_cfg,
        target_override=replay_target,
        suite=suite_cfg,
        judge=judge_cfg,
        output_dir=pathlib.Path(output),
        offline=True,
        seed=manifest.seed,
    )

    # Run replay scan
    async def _do_replay() -> ScanResult:
        from rtl.runner import run_scan

        return await run_scan(options)

    result = asyncio.run(_do_replay())

    console.print(
        f"[green]Replay complete:[/green] {result.summary.total} probes, "
        f"{result.summary.succeeded} succeeded, "
        f"{result.summary.refused} refused"
    )
    console.print(f"[cyan]Replay reports written to:[/cyan] {options.output_dir}")


@app.command("benchmark")
def benchmark_cmd(
    version: int = typer.Option(3, help="Dataset version (1, 2, or 3)"),
    judge_mode: str = typer.Option("heuristic", help="heuristic / llm / auto"),
    judge_model: str | None = typer.Option(None, help="Judge model spec if mode=llm"),
) -> None:
    """Benchmark judge detection quality against versioned golden datasets."""
    from rtl.evaluation.harness import dataset_path, format_report, run_dataset
    from rtl.evaluation.judge import Judge

    judge_target = None
    if judge_mode in ("auto", "llm") and judge_model:
        judge_target = TargetConfig.parse(judge_model).build_target()
    judge = Judge(judge_target=judge_target, mode=judge_mode)

    try:
        path = dataset_path(version)
    except Exception as exc:
        console.print(f"[red]Failed to load dataset v{version}: {exc}[/red]")
        raise typer.Exit(1) from None

    console.print(f"[bold cyan]Running benchmark on golden dataset v{version}:[/bold cyan] {path.name}")
    metrics = run_dataset(judge, path)
    report_text = format_report(metrics, version=version)
    console.print(report_text)


@app.command("diff")
def diff_cmd(
    baseline_file: str = typer.Argument(..., help="Path to baseline report.json"),
    candidate_file: str = typer.Argument(..., help="Path to candidate report.json"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output path for markdown diff report"),
) -> None:
    """Compare two scan results and identify fixed vulnerabilities & regressions."""
    from rtl.reporting.diff import compare_scans, render_diff_markdown
    from rtl.reporting.json_reporter import load_json

    base_path = pathlib.Path(baseline_file)
    cand_path = pathlib.Path(candidate_file)
    if not base_path.is_file():
        console.print(f"[red]Baseline report not found: {base_path}[/red]")
        raise typer.Exit(1)
    if not cand_path.is_file():
        console.print(f"[red]Candidate report not found: {cand_path}[/red]")
        raise typer.Exit(1)

    base_res = load_json(base_path)
    cand_res = load_json(cand_path)

    diff = compare_scans(base_res, cand_res)

    is_comp = diff.get("is_comparable", True)
    table_title = "Scan Comparison (Security Regression Diff)" if is_comp else "Cross-Target Differential Comparison"
    table = Table(title=table_title)
    table.add_column("Metric", style="cyan")
    table.add_column("Baseline", justify="right")
    table.add_column("Candidate", justify="right")
    table.add_column("Delta", justify="right", style="bold")

    delta_str = f"{diff['success_delta']:+d}"
    table.add_row(
        "Vulnerabilities Landed",
        str(diff["baseline_succeeded"]),
        str(diff["candidate_succeeded"]),
        delta_str,
    )
    table.add_row("Fixed Vulnerabilities", "—", "—", f"[green]{diff['fixed_count']}[/green]")
    reg_color = "red" if is_comp else "yellow"
    reg_label = diff.get("regression_label", "Regressions (New Failures)")
    table.add_row(reg_label, "—", "—", f"[{reg_color}]{diff['regression_count']}[/{reg_color}]")
    table.add_row("Persisting Vulnerabilities", "—", "—", f"[yellow]{diff['persisting_count']}[/yellow]")
    console.print(table)

    if not is_comp:
        console.print(
            "[bold yellow]Notice: Cross-target comparison detected. Baseline and candidate targets differ; "
            "differences reflect model/architecture divergence rather than single-system security regressions."
            "[/bold yellow]"
        )
    elif diff["regressions"]:
        console.print(
            f"[bold red]Alert: {diff['regression_count']} regression(s) introduced in candidate scan![/bold red]"
        )
        for r in diff["regressions"]:
            console.print(f"  [red]↳ {r['attack_id']}: {r['name']} ({r['severity'].upper()})[/red]")

    if output:
        render_diff_markdown(diff, output)
        console.print(f"[green]Diff markdown written to:[/green] {output}")


@app.command("campaign")
def campaign_cmd(
    targets: str = typer.Option("mock:model-a,mock:model-b", help="Comma-separated target specs, e.g. mock:a,mock:b"),
    suite: str | None = typer.Option(None, help="Suite name or path (default: quick)"),
    planner: str = typer.Option("ev_adaptive", help="Planner: ev_adaptive / adaptive / heuristic"),
    budget_probes: int = typer.Option(10, help="Maximum probe execution budget per target"),
    budget_turns: int = typer.Option(10, help="Maximum multi-turn step budget per target"),
    budget_seconds: float = typer.Option(60.0, help="Maximum execution time budget per target"),
    active_profiling: bool = typer.Option(
        True,
        "--active-profiling/--no-active-profiling",
        help="Run pre-campaign active capability profiling",
    ),
    output_dir: str = typer.Option("reports/campaigns", help="Output directory for campaign artifacts"),
    seed: int = typer.Option(42, help="Deterministic random seed"),
    resume: str | None = typer.Option(None, "--resume", help="Path to checkpoint file to resume from"),
) -> None:
    """Run an autonomous evidence-driven red teaming campaign with differential analysis."""
    from rtl.attacks.loader import resolve
    from rtl.campaign.manager import CampaignManager
    from rtl.campaign.models import CampaignConfig
    from rtl.config import BudgetLimits, Suite

    resume_results = None
    if resume:
        resume_cfg, resume_results = CampaignManager.load_checkpoint(resume)
        config = resume_cfg
        campaign_id = config.campaign_id
        target_specs = [f"{t['provider']}:{t['model']}" for t in config.targets]
        parsed_targets = config.targets
        target_instances = {
            t["target_id"]: TargetConfig.parse(f"{t['provider']}:{t['model']}").build_target() for t in parsed_targets
        }
        probes = resolve()
    else:
        # 1. Resolve suite & probes
        suite_path = _find_suite(suite or "quick")
        suite_cfg = Suite.load(suite_path)
        probes = resolve(
            categories=list(suite_cfg.categories) if suite_cfg.categories else None,
            attack_ids=list(suite_cfg.attack_ids) if suite_cfg.attack_ids else None,
        )
        if not probes:
            console.print("[red]No attack probes found in suite.[/red]")
            raise typer.Exit(1)

        # 2. Parse target specifications
        target_specs = [t.strip() for t in targets.split(",") if t.strip()]
        if not target_specs:
            console.print("[red]At least one target must be specified.[/red]")
            raise typer.Exit(1)

        parsed_targets = []
        target_instances = {}
        for spec in target_specs:
            t_cfg = TargetConfig.parse(spec)
            tid = f"{t_cfg.kind}:{t_cfg.model}"
            parsed_targets.append(
                {
                    "target_id": tid,
                    "provider": t_cfg.kind,
                    "model": t_cfg.model,
                }
            )
            target_instances[tid] = t_cfg.build_target()

        campaign_id = f"cmp-{pathlib.Path(suite_path).stem}-{int(time.time())}"
        config = CampaignConfig(
            campaign_id=campaign_id,
            targets=parsed_targets,
            planner=planner,
            budget=BudgetLimits(
                max_probes=budget_probes,
                max_turns=budget_turns,
                max_seconds=budget_seconds,
            ),
            active_profiling=active_profiling,
            output_dir=output_dir,
            seed=seed,
        )

    manager = CampaignManager(config=config, probes=probes)
    console.print(f"[bold cyan]Launching Red Team Campaign:[/bold cyan] {campaign_id}")
    specs_str = ", ".join(target_specs)
    console.print(
        f"Targets: {specs_str} | Planner: {config.planner} | Per-Target Budget: {config.budget.max_probes} probes"
    )

    out_path = pathlib.Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_file = out_path / f"{campaign_id}.json"

    result = asyncio.run(
        manager.execute(
            target_instances=target_instances,
            checkpoint_path=report_file,
            resume_results=resume_results,
        )
    )

    # Render results table
    table = Table(title=f"Campaign Summary: {campaign_id}")
    table.add_column("Target", style="cyan")
    table.add_column("Probes Run", justify="right")
    table.add_column("Confirmed", justify="right", style="bold red")
    table.add_column("Corroborated", justify="right", style="yellow")
    table.add_column("Disproven", justify="right", style="green")
    table.add_column("Evidence DAG Integrity", justify="center")

    for tid, tres in result.target_results.items():
        table.add_row(
            tid,
            str(tres.total_probes_run),
            str(tres.confirmed_findings_count),
            str(tres.corroborated_findings_count),
            str(tres.disproven_findings_count),
            "[green]VERIFIED[/green]" if tres.evidence_graph_verified else "[red]FAILED[/red]",
        )
    console.print(table)

    # Render differential report if available
    if result.differential and len(parsed_targets) >= 2:
        diff_table = Table(title="Differential Security Analysis")
        diff_table.add_column("Probe ID", style="bold")
        diff_table.add_column("Category")
        diff_table.add_column("Divergence Type", style="yellow")
        diff_table.add_column("Target Outcomes")

        for asym in result.differential.asymmetric_findings:
            outcomes_str = " | ".join(f"{t}: {s}" for t, s in asym.target_outcomes.items())
            diff_table.add_row(
                asym.probe_id,
                asym.category,
                asym.divergence_type,
                outcomes_str,
            )
        console.print(diff_table)
        console.print(f"[bold]{result.differential.summary}[/bold]")

    # Export Campaign Artifacts
    out_path = pathlib.Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_file = out_path / f"{campaign_id}.json"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(result.model_dump_json(indent=2))
    console.print(f"[green]Campaign summary saved to:[/green] {report_file}")


@app.command("profile")
def profile_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Target spec, e.g. mock:echo or ollama:llama3.1"),
    probe: bool = typer.Option(True, "--probe/--no-probe", help="Run active diagnostic capability probing"),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional path to export target profile JSON"),
) -> None:
    """Discover, analyze, and inspect the security capabilities of a target system."""
    from rtl.config import TargetConfig
    from rtl.profiler.detector import ActiveProfiler
    from rtl.profiler.models import TargetProfile

    t_cfg = TargetConfig.parse(target)
    target_instance = t_cfg.build_target()
    tid = f"{t_cfg.kind}:{t_cfg.model}"

    console.print(f"[bold cyan]Profiling target capability envelope:[/bold cyan] {tid}")
    if probe:
        profile = asyncio.run(ActiveProfiler.profile_target(target_instance, target_id=tid))
    else:
        profile = TargetProfile(target_id=tid, provider=t_cfg.kind, model=t_cfg.model)

    table = Table(title=f"Target Security Capability Profile: {tid}")
    table.add_column("Capability", style="cyan")
    table.add_column("Confidence Level", style="bold")
    table.add_column("Evidentiary Basis / Notes")

    for cap_name, entry in profile.capabilities.items():
        conf_style = (
            "green"
            if entry.confidence in ("known", "observed")
            else "yellow"
            if entry.confidence == "inferred"
            else "dim"
        )
        notes_str = "; ".join(entry.notes) if entry.notes else "—"
        table.add_row(
            cap_name,
            f"[{conf_style}]{entry.confidence.upper()}[/{conf_style}]",
            notes_str,
        )
    console.print(table)

    if output:
        p = pathlib.Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]Target profile saved to:[/green] {output}")


@app.command("evidence")
def evidence_cmd(
    report_file: str = typer.Argument(..., help="Path to report.json or campaign_*.json"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify cryptographic hash integrity"),
    export_dot: str | None = typer.Option(None, "--export-dot", help="Export Graphviz DOT graph file"),
) -> None:
    """Inspect and cryptographically verify evidence DAGs and confirmation lineage."""
    from rtl.core.evidence_graph import EvidenceGraph

    p = pathlib.Path(report_file)
    if not p.is_file():
        console.print(f"[red]Report file not found: {report_file}[/red]")
        raise typer.Exit(1)

    with open(p, encoding="utf-8") as f:
        data = json.load(f)

    graphs: list[tuple[str, EvidenceGraph]] = []
    if "target_results" in data:
        for tid, tres in data["target_results"].items():
            if "evidence_graph" in tres:
                graphs.append((tid, EvidenceGraph.model_validate(tres["evidence_graph"])))
    elif "findings" in data:
        console.print(f"[cyan]Loaded report:[/cyan] {p.name} with {len(data.get('findings', []))} findings")
        if "adaptive" in data and isinstance(data["adaptive"], dict) and "evidence_graph" in data["adaptive"]:
            target_name = data.get("meta", {}).get("target_spec", "target")
            graphs.append((target_name, EvidenceGraph.model_validate(data["adaptive"]["evidence_graph"])))

    if not graphs:
        console.print("[yellow]No serialized evidence DAG found in the supplied report.[/yellow]")
        return

    for tid, graph in graphs:
        console.print(
            f"[bold cyan]Evidence Graph for Target:[/bold cyan] {tid} "
            f"({len(graph.nodes)} nodes, {len(graph.edges)} edges)"
        )
        if verify:
            valid, msg = graph.verify_integrity()
            status_str = (
                "[green]VERIFIED (Integrity Valid)[/green]" if valid else f"[bold red]FAILED ({msg})[/bold red]"
            )
            console.print(f"  Lineage Integrity: {status_str}")

        if export_dot:
            dot_path = pathlib.Path(export_dot)
            dot_path.parent.mkdir(parents=True, exist_ok=True)
            if len(graphs) == 1:
                target_dot_path = dot_path
            else:
                safe_tid = tid.replace(":", "_").replace("/", "_")
                target_dot_path = dot_path.with_name(f"{dot_path.stem}_{safe_tid}{dot_path.suffix}")
            target_dot_path.write_text(graph.to_dot(), encoding="utf-8")
            console.print(f"  [green]Graphviz DOT exported to:[/green] {target_dot_path}")


@app.command("version")
def version_cmd() -> None:
    """Print the installed version."""
    from rtl._version import __version__

    console.print(f"rtl v{__version__}")


def _provider_defaults() -> dict[str, str]:
    from rtl.config import DEFAULT_MODELS

    return dict(DEFAULT_MODELS)


def _find_suite(name: str) -> pathlib.Path:
    from rtl.config import bundled_suites_dir

    p = pathlib.Path(name)
    if p.is_file():
        return p
    filename = name if name.endswith((".yaml", ".yml")) else f"{name}.yaml"
    return bundled_suites_dir() / filename


def main() -> None:
    app()


__all__ = ["app", "main"]
