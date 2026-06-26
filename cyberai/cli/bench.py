"""
`cyberai bench` — run CyberAI against its own local vulnerable-target suite
and report an honest pass@1. This is the public, reproducible measurement
surface: no third-party benchmark required, results are deterministic given a
fixed engine.

Subcommands:
  bench list                 list available suites and their targets
  bench run [--suite local]  build targets, run the engine, print a scorecard
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from cyberai.bench.runner import BenchResult, run_suite
from cyberai.bench.targets import LocalSuiteAdapter
from cyberai.bench.engine_runner import make_engine_runner
from cyberai.bench.ctf_loader import CTFAdapter
from cyberai.bench.scorecard import RunMeta, generate_scorecard

console = Console()

# Suite registry: name -> adapter factory. External adapters (CVE-Bench, ...)
# register here later without touching the CLI.
_SUITES = {
    "local": LocalSuiteAdapter,
    "ctf": CTFAdapter,
}


@click.group()
def bench() -> None:
    """Benchmark the engine against vulnerable targets (honest pass@1).

    \b
    Examples:
      cyberai bench list
      cyberai bench run --suite local
      cyberai bench run --suite local --engine real
      cyberai bench run --suite local --scorecard reports/scorecard.md

    Results are reproducible: targets ship in this repo, success is binary
    (a real signal from a responding target), and every run can emit a
    Markdown scorecard with engine/provider/model provenance.
    """


@bench.command("list")
def list_suites() -> None:
    """List available benchmark suites and their tasks."""
    for name, factory in _SUITES.items():
        adapter = factory()
        tasks = adapter.load_tasks()
        table = Table(title=f"suite: {name}  ({len(tasks)} tasks)")
        table.add_column("task id", style="cyan")
        table.add_column("name")
        table.add_column("class", style="magenta")
        table.add_column("target")
        for t in tasks:
            table.add_row(t.id, t.name, t.metadata.get("vuln_class", "?"), t.target)
        console.print(table)


def _placeholder_runner(task) -> BenchResult:
    """Default runner used until the live engine path is wired (day 6+).

    It does NOT fake success: every task is reported unsolved so the scorecard
    never overstates capability. Replaced by the real engine runner later.
    """
    return BenchResult(
        task_id=task.id,
        suite=task.suite,
        solved=False,
        details={"note": "engine runner not yet wired; reported as unsolved"},
    )


@bench.command("run")
@click.option(
    "--suite",
    default="local",
    show_default=True,
    type=click.Choice(sorted(_SUITES)),
    help="Which benchmark suite to run.",
)
@click.option(
    "--scorecard",
    "scorecard_path",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Write a reproducible Markdown scorecard to this path.",
)
@click.option(
    "--engine",
    "engine",
    default="placeholder",
    show_default=True,
    type=click.Choice(["placeholder", "real"]),
    help="placeholder reports all-unsolved; real runs live probes (local suite).",
)
def run(suite: str, scorecard_path: str | None, engine: str) -> None:
    """Run a suite and print a pass@1 scorecard."""
    adapter = _SUITES[suite]()
    if engine == "real" and isinstance(adapter, LocalSuiteAdapter):
        runner = make_engine_runner(adapter)
    else:
        if engine == "real":
            console.print(
                "[yellow]⚠ real engine supports the local suite only; using placeholder[/yellow]"
            )
        runner = _placeholder_runner
    report = run_suite(adapter, runner)

    table = Table(title=f"bench: {suite}")
    table.add_column("task id", style="cyan")
    table.add_column("solved")
    table.add_column("time (s)", justify="right")
    for r in report.results:
        mark = "[green]✓[/green]" if r.solved else "[red]✗[/red]"
        table.add_row(r.task_id, mark, f"{r.duration_s:.2f}")
    console.print(table)
    console.print(f"[bold]pass@1: {report.solved}/{report.total} = {report.pass_at_1:.1%}[/bold]")

    if scorecard_path:
        md = generate_scorecard(
            report, RunMeta(note="cyberai bench run", extra={"engine": engine, "suite": suite})
        )
        out = Path(scorecard_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md)
        console.print(f"[dim]scorecard written to {out}[/dim]")
