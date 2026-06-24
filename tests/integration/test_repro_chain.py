"""
End-to-end reproducibility chain: manifest -> budget -> regression gate.

Proves the Day-5 honesty lock holds together:
  - two identical runs produce the SAME manifest fingerprint (reproducible),
  - a populated budget rolls up correctly,
  - the regression gate passes a held score and fails a dropped one,
  - a silently-swapped suite is caught even when the score is unchanged.
"""

from __future__ import annotations

from cyberai.bench.regression_gate import check_regression
from cyberai.bench.run_budget import summarize_budget
from cyberai.bench.run_manifest import RunConfig, build_manifest, set_global_seed
from cyberai.bench.runner import BenchResult, SuiteReport, run_suite
from cyberai.bench.targets import LocalSuiteAdapter
from cyberai.core.cost_tracker import CostTracker


def _half_runner(task) -> BenchResult:
    # deterministic: solve sqli, fail the rest -> stable score
    return BenchResult(task_id=task.id, suite=task.suite, solved="sqli" in task.id)


def test_two_identical_runs_share_fingerprint():
    set_global_seed(1337)
    adapter = LocalSuiteAdapter()
    tasks = adapter.load_tasks()
    cfg = RunConfig(model="m", provider="p", temperature=0.0, seed=1337)

    r1 = run_suite(adapter, _half_runner)
    m1 = build_manifest("local", tasks, r1, cfg, timestamp="2026-01-01T00:00:00Z")

    set_global_seed(1337)
    r2 = run_suite(adapter, _half_runner)
    m2 = build_manifest("local", tasks, r2, cfg, timestamp="2026-06-25T12:00:00Z")

    # same identity despite different timestamps
    assert m1.manifest_hash == m2.manifest_hash
    assert m1.suite_hash == m2.suite_hash
    assert m1.solved == m2.solved


def test_budget_rolls_into_run():
    t = CostTracker()
    t.add("recon", "gpt-4o-mini", input_tokens=1200, output_tokens=300)
    b = summarize_budget(t, tasks=3)
    assert b.total_tokens == 1500
    assert b.tasks == 3
    assert b.cost_per_task >= 0.0


def test_gate_passes_held_and_fails_dropped():
    adapter = LocalSuiteAdapter()
    tasks = adapter.load_tasks()
    cfg = RunConfig()

    baseline = build_manifest("local", tasks, run_suite(adapter, _half_runner), cfg)

    # identical run -> held -> pass
    held = build_manifest("local", tasks, run_suite(adapter, _half_runner), cfg)
    assert check_regression(held, baseline).passed is True

    # zero-solve run -> regressed -> fail
    dropped_report = SuiteReport(
        suite="local",
        total=baseline.total,
        solved=0,
        results=tuple(BenchResult(t.id, "local", False) for t in tasks),
    )
    dropped = build_manifest("local", tasks, dropped_report, cfg)
    assert check_regression(dropped, baseline).passed is False


def test_gate_catches_silent_suite_swap():
    adapter = LocalSuiteAdapter()
    tasks = adapter.load_tasks()
    baseline = build_manifest("local", tasks, run_suite(adapter, _half_runner), RunConfig())

    # same score, but a different (smaller/easier) task set -> different suite_hash
    fewer = tasks[:1]
    swapped_report = SuiteReport(
        suite="local",
        total=1,
        solved=baseline.solved,
        results=(BenchResult(fewer[0].id, "local", True),),
    )
    swapped = build_manifest("local", fewer, swapped_report, RunConfig())
    assert check_regression(swapped, baseline).passed is False
    assert check_regression(swapped, baseline).suite_changed is True
