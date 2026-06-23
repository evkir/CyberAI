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
from cyberai.bench.scorecard import RunMeta, generate_scorecard

console = Console()

# Suite registry: name -> adapter factory. External adapters (CVE-Bench, ...)
# register here later without touching the CLI.
_SUITES = {
    "local": LocalSuiteAdapter,
}


@click.group()
def bench() -> None:
    """Benchmark the engine against vulnerable targets (honest pass@1)."""


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
def run(suite: str, scorecard_path: str | None) -> None:
    """Run a suite and print a pass@1 scorecard."""
    adapter = _SUITES[suite]()
    report = run_suite(adapter, _placeholder_runner)

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
        md = generate_scorecard(report, RunMeta(note="cyberai bench run"))
        out = Path(scorecard_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md)
        console.print(f"[dim]scorecard written to {out}[/dim]")
