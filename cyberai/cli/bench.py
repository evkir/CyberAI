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
from cyberai.bench.agent_engine import make_agent_runner
from cyberai.bench.cve_bench import CVEBenchAdapter
from cyberai.bench.cve_bench_runner import make_cve_bench_runner
from cyberai.bench.engine_runner import make_engine_runner
from cyberai.bench.ctf_loader import CTFAdapter
from cyberai.bench.scorecard import RunMeta, generate_scorecard

console = Console()

# How a probe verdict renders beside the agent's; unknown stays unknown.
_JUDGE_MARK = {True: "[green]✓[/green]", False: "[red]✗[/red]", None: "[dim]?[/dim]"}

# Suite registry: name -> adapter factory. External adapters (CVE-Bench, ...)
# register here later without touching the CLI.
_SUITES = {
    "local": LocalSuiteAdapter,
    "ctf": CTFAdapter,
    "cve-bench": CVEBenchAdapter,
}


@click.group()
def bench() -> None:
    """Benchmark the engine against vulnerable targets (honest pass@1).

    \b
    Examples:
      cyberai bench list
      cyberai bench run --suite local
      cyberai bench run --suite local --engine real
      cyberai bench run --suite local --engine agent
      cyberai bench run --suite local --scorecard reports/scorecard.md
      cyberai bench run --suite cve-bench --engine agent

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
        reason = getattr(adapter, "unavailable_reason", None)
        if not tasks and reason:
            # An empty external suite is a missing dependency, not a verdict.
            console.print(f"[dim]suite: {name} unavailable — {reason}[/dim]")
            continue
        table = Table(title=f"suite: {name}  ({len(tasks)} tasks)")
        table.add_column("task id", style="cyan")
        table.add_column("name")
        table.add_column("class", style="magenta")
        table.add_column("target")
        for t in tasks:
            table.add_row(t.id, t.name, t.metadata.get("vuln_class", "?"), t.target)
        console.print(table)


def _placeholder_runner(task) -> BenchResult:
    """Default runner used until the live engine path is wired.

    It does NOT fake success: every task is reported unsolved so the scorecard
    never overstates capability. Replaced by the real engine runner later.
    """
    return BenchResult(
        task_id=task.id,
        suite=task.suite,
        solved=False,
        details={"note": "engine runner not yet wired; reported as unsolved"},
    )


# Engines that need a live target: name -> runner factory over the adapter.
_LIVE_ENGINES = {
    "real": make_engine_runner,
    "agent": make_agent_runner,
}


def _select_runner(engine: str, adapter):
    """Resolve an engine and suite to a runner, degrading honestly.

    Each suite brings its own targets and its own authority on success:
    cve-bench is scored by the grader shipped inside its containers, the local
    suite by our probes or our agent. Where a combination has no live path, the
    all-unsolved placeholder runs rather than something that quietly measures
    a different thing.
    """
    if engine == "placeholder":
        return _placeholder_runner
    if isinstance(adapter, CVEBenchAdapter):
        # Upstream owns the grader, so there is no probe-only mode to offer.
        if engine != "agent":
            console.print(
                "[yellow]⚠ cve-bench is scored by its own grader; use --engine agent[/yellow]"
            )
            return _placeholder_runner
        return make_cve_bench_runner(adapter)
    factory = _LIVE_ENGINES.get(engine)
    if factory is None:
        return _placeholder_runner
    if not isinstance(adapter, LocalSuiteAdapter):
        console.print(
            f"[yellow]⚠ the {engine} engine supports the local suite only; "
            "using placeholder[/yellow]"
        )
        return _placeholder_runner
    return factory(adapter)


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
    type=click.Choice(["placeholder", "real", "agent"]),
    help=(
        "placeholder reports all-unsolved; real runs the fixed probes; agent "
        "runs the CyberAI pipeline and cross-checks it against those probes "
        "(real and agent: local suite only)."
    ),
)
def run(suite: str, scorecard_path: str | None, engine: str) -> None:
    """Run a suite and print a pass@1 scorecard."""
    adapter = _SUITES[suite]()
    runner = _select_runner(engine, adapter)
    report = run_suite(adapter, runner)

    table = Table(title=f"bench: {suite}")
    table.add_column("task id", style="cyan")
    table.add_column("solved")
    table.add_column("time (s)", justify="right")
    if engine == "agent":
        # The agent verdict is the score; the probe sits beside it so a gap
        # between the two is visible in the run, not only in the JSON.
        table.add_column("probe")
    for r in report.results:
        mark = "[green]✓[/green]" if r.solved else "[red]✗[/red]"
        row = [r.task_id, mark, f"{r.duration_s:.2f}"]
        if engine == "agent":
            row.append(_JUDGE_MARK[r.details.get("judge_solved")])
        table.add_row(*row)
    console.print(table)
    console.print(f"[bold]pass@1: {report.solved}/{report.total} = {report.pass_at_1:.1%}[/bold]")

    if engine == "agent":
        for r in report.results:
            note = r.details.get("disagreement")
            if note:
                console.print(f"[yellow]disagreement on {r.task_id}: {note}[/yellow]")

    if scorecard_path:
        md = generate_scorecard(
            report, RunMeta(note="cyberai bench run", extra={"engine": engine, "suite": suite})
        )
        out = Path(scorecard_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md)
        console.print(f"[dim]scorecard written to {out}[/dim]")
