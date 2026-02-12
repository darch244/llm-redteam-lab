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
import pathlib
from typing import TYPE_CHECKING, Literal, cast

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
    redact: bool = typer.Option(True, help="Scrub secrets in reports"),
    log_level: str = typer.Option("INFO", help="Log verbosity"),
) -> None:
    """Run an attack suite against a target and produce JSON + HTML reports."""
    setup_logging(log_level)
    target_cfg = TargetConfig.parse(target)
    suite_path = suite or str(_find_suite("quick.yaml"))
    suite_cfg = Suite.load(suite_path)
    if categories:
        suite_cfg = suite_cfg.model_copy(update={"categories": list(categories)})
    if attack_ids:
        suite_cfg = suite_cfg.model_copy(update={"attack_ids": list(attack_ids), "categories": []})
    judge_cfg = JudgeConfig(
        mode=cast(Literal["auto", "llm", "heuristic"], judge_mode)
        if judge_mode in ("auto", "llm", "heuristic")
        else "auto",
        model=judge_model,
    )
    from rtl.config import ScanOptions

    options = ScanOptions(
        target=target_cfg,
        suite=suite_cfg,
        judge=judge_cfg,
        output_dir=pathlib.Path(output),
        offline=offline,
        redact=redact,
        max_prompt_len=max_prompt_len,
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
    output: str = typer.Option(None, help="Output path (default: <input>.html)"),
    format: str = typer.Option("html", help="html / json / pdf"),
) -> None:
    """Regenerate HTML/PDF from an existing report.json."""
    from rtl.reporting.json_reporter import load_json

    result = load_json(input_file)
    dest = pathlib.Path(output) if output else pathlib.Path(input_file).with_suffix(f".{format}")
    if format == "json":
        from rtl.reporting.json_reporter import write_json

        write_json(result, dest)
    elif format == "pdf":
        from rtl.reporting.pdf_reporter import render_pdf

        render_pdf(result, dest)
    else:
        from rtl.reporting.html_reporter import render_html

        render_html(result, dest)
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

    return bundled_suites_dir() / name


def main() -> None:
    app()


__all__ = ["app", "main"]
