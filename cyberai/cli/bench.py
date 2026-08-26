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

from cyberai.bench.agent_engine import make_agent_runner
from cyberai.bench.ctf_loader import CTFAdapter
from cyberai.bench.cve_bench import CVEBenchAdapter
from cyberai.bench.cve_bench_runner import make_cve_bench_runner
from cyberai.bench.engine_runner import make_engine_runner
from cyberai.bench.regression_gate import check_regression, load_baseline
from cyberai.bench.run_manifest import (
    DEFAULT_SEED,
    RunConfig,
    build_manifest,
    set_global_seed,
)
from cyberai.bench.runner import BenchResult, run_suite
from cyberai.bench.scorecard import RunMeta, generate_scorecard
from cyberai.bench.targets import LocalSuiteAdapter

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


def _select_runner(engine: str, adapter, mode: str = "zero-day"):
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
        return make_cve_bench_runner(adapter, one_day=mode == "one-day")
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


def _second_opinion(details: dict) -> bool | None:
    """The verdict that did *not* set the score, or None if there was none.

    Which side that is depends on the suite: on the local suite the agent
    scores and the probe checks it, on cve-bench the upstream grader scores
    and our agent is the one being checked. Reading only one key rendered a
    grader that answered as a grader that could not be reached, which is the
    exact distinction the runner goes out of its way to preserve.
    """
    if "judge_solved" in details:
        return details["judge_solved"]
    if "grader_status" in details and details.get("available"):
        return bool(details.get("agent_confirmed", 0))
    return None


def _model_participation(report) -> tuple[int | None, str | None]:
    """What the whole run can say about the model, or nothing.

    Per-task facts only roll up when they agree. A run where some tasks
    reached a model and others could not has no single answer, and picking
    either one publishes a number the run did not produce -- so the split
    itself is what travels. Absent everywhere stays absent: a scorecard with
    no row is honest about not having measured, a row reading `unknown` is
    a value.
    """
    results = list(report.results)
    proven = [r for r in results if r.details.get("llm_calls") == 0]
    if not proven:
        # Also the empty-suite answer, and deliberately the same one: an
        # external suite whose checkout is absent scores 0/0 and reaches
        # here, and it has exactly as little to say about a model as a
        # suite that ran and counted nothing.
        return None, None
    if len(proven) == len(results):
        reasons = {str(r.details.get("llm_zero_reason")) for r in proven}
        return 0, reasons.pop() if len(reasons) == 1 else "mixed_reasons"
    return None, f"mixed: {len(proven)} of {len(results)} tasks reached no model"


def _select_tasks(tasks: list, wanted: tuple[str, ...]) -> list:
    """Narrow a suite to the requested ids, or fail loudly.

    An unknown id is an error rather than an empty run: a typo that silently
    scores zero tasks looks exactly like a suite nobody can solve.
    """
    if not wanted:
        return tasks
    known = {t.id for t in tasks}
    missing = [w for w in wanted if w not in known]
    if missing:
        sample = ", ".join(sorted(known)[:5]) if known else "none (the suite is empty)"
        raise click.BadParameter(
            f"unknown task id(s): {', '.join(missing)}. Known ids include: {sample}",
            param_hint="--task",
        )
    return [t for t in tasks if t.id in set(wanted)]


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
    "--task",
    "task_ids",
    multiple=True,
    help="Run only these task ids. Repeatable. The score then covers the selection only.",
)
@click.option(
    "--baseline",
    "baseline_path",
    default=None,
    type=click.Path(dir_okay=False),
    help="Fail the run if the solve-rate regressed against this manifest.",
)
@click.option(
    "--manifest",
    "manifest_path",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Write a run manifest (provenance + fingerprint) to this JSON path.",
)
@click.option(
    "--seed",
    "seed",
    default=DEFAULT_SEED,
    show_default=True,
    type=int,
    help="Pin process-wide randomness so a run can be reproduced.",
)
@click.option(
    "--mode",
    "mode",
    default="zero-day",
    show_default=True,
    type=click.Choice(["zero-day", "one-day"]),
    help=(
        "zero-day gives the agent an address and nothing else; one-day also "
        "gives it what the CVE is, which separates not finding a flaw from not "
        "exploiting one that was pointed at (cve-bench only)."
    ),
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
def run(
    suite: str,
    scorecard_path: str | None,
    engine: str,
    mode: str = "zero-day",
    manifest_path: str | None = None,
    baseline_path: str | None = None,
    seed: int = DEFAULT_SEED,
    task_ids: tuple[str, ...] = (),
) -> None:
    """Run a suite and print a pass@1 scorecard."""
    # Before anything samples: PYTHONHASHSEED only reaches children spawned
    # after this call, and the engines spawn containers.
    set_global_seed(seed)
    adapter = _SUITES[suite]()
    if mode == "one-day" and not isinstance(adapter, CVEBenchAdapter):
        # Only cve-bench tasks carry a description. Reporting the run as
        # one-day when nothing was told to the agent would name a mode that
        # did not happen, so the label falls back with the behaviour.
        console.print(
            "[yellow]\u26a0 one-day needs a suite that describes its "
            "vulnerabilities; running zero-day[/yellow]"
        )
        mode = "zero-day"
    runner = _select_runner(engine, adapter, mode)
    all_tasks = adapter.load_tasks()
    selected = _select_tasks(all_tasks, task_ids)
    filtered = len(selected) != len(all_tasks)
    if filtered:
        console.print(
            f"[yellow]filtered: {len(selected)} of {len(all_tasks)} tasks \u2014 the score "
            "below covers the selection, not the suite[/yellow]"
        )
    report = run_suite(adapter, runner, tasks=selected)

    table = Table(title=f"bench: {suite}")
    table.add_column("task id", style="cyan")
    table.add_column("solved")
    table.add_column("time (s)", justify="right")
    if engine == "agent":
        # Whichever verdict did not set the score sits beside it, so a gap
        # between the two is visible in the run and not only in the JSON.
        second = "agent" if suite == "cve-bench" else "probe"
        table.add_column(second)
    for r in report.results:
        mark = "[green]✓[/green]" if r.solved else "[red]✗[/red]"
        row = [r.task_id, mark, f"{r.duration_s:.2f}"]
        if engine == "agent":
            row.append(_JUDGE_MARK[_second_opinion(r.details)])
        table.add_row(*row)
    console.print(table)
    console.print(f"[bold]pass@1: {report.solved}/{report.total} = {report.pass_at_1:.1%}[/bold]")

    if engine == "agent":
        for r in report.results:
            note = r.details.get("disagreement")
            if note:
                console.print(f"[yellow]disagreement on {r.task_id}: {note}[/yellow]")

    manifest = None
    if manifest_path or baseline_path:
        # `selected`, not `all_tasks`: the suite hash has to describe what was
        # actually run, or a filtered run would fingerprint as the full suite
        # and the regression gate would compare two different things.
        manifest = build_manifest(
            suite=suite,
            tasks=selected,
            report=report,
            config=RunConfig(seed=seed, extra={"engine": engine, "mode": mode}),
        )

    if manifest_path and manifest is not None:
        mpath = Path(manifest_path)
        mpath.parent.mkdir(parents=True, exist_ok=True)
        mpath.write_text(manifest.to_json())
        console.print(f"[dim]manifest written to {mpath} ({manifest.manifest_hash[:12]})[/dim]")

    if scorecard_path:
        extra = {"engine": engine, "suite": suite, "seed": str(seed), "mode": mode}
        if filtered:
            # A scorecard outlives the terminal it was printed in; the narrowed
            # denominator has to travel with it.
            extra["filtered"] = f"{len(selected)} of {len(all_tasks)} tasks: " + ", ".join(
                t.id for t in selected
            )
        calls, reason = _model_participation(report)
        md = generate_scorecard(
            report,
            RunMeta(
                note="cyberai bench run",
                extra=extra,
                llm_calls=calls,
                llm_zero_reason=reason,
            ),
        )
        out = Path(scorecard_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md)
        console.print(f"[dim]scorecard written to {out}[/dim]")

    if baseline_path and manifest is not None:
        # Last, so the manifest and scorecard are on disk even when the gate
        # fails: a regression is exactly when the artefacts are wanted.
        gate = check_regression(manifest, load_baseline(baseline_path))
        if gate.passed:
            console.print(f"[green]regression gate: {gate.reason}[/green]")
        else:
            console.print(f"[red]regression gate failed: {gate.reason}[/red]")
            raise SystemExit(1)
