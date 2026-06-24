"""Tests for the benchmark run manifest (determinism + provenance)."""

from __future__ import annotations

import random

from cyberai.bench.run_manifest import (
    DEFAULT_SEED,
    RunConfig,
    build_manifest,
    hash_tasks,
    set_global_seed,
)
from cyberai.bench.runner import BenchResult, BenchTask, SuiteReport


def _tasks() -> list[BenchTask]:
    return [
        BenchTask(id="t1", suite="s", target="x", name="one", success_criteria="a"),
        BenchTask(id="t2", suite="s", target="y", name="two", success_criteria="b"),
    ]


def _report(solved: int = 1, total: int = 2) -> SuiteReport:
    results = (
        BenchResult("t1", "s", True),
        BenchResult("t2", "s", solved == 2),
    )
    return SuiteReport(suite="s", total=total, solved=solved, results=results)


def test_set_global_seed_is_repeatable():
    set_global_seed(DEFAULT_SEED)
    a = [random.random() for _ in range(5)]
    set_global_seed(DEFAULT_SEED)
    b = [random.random() for _ in range(5)]
    assert a == b


def test_hash_tasks_order_independent():
    t = _tasks()
    assert hash_tasks(t) == hash_tasks(list(reversed(t)))


def test_hash_tasks_changes_when_suite_changes():
    base = hash_tasks(_tasks())
    swapped = _tasks() + [
        BenchTask(id="t3", suite="s", target="z", name="three", success_criteria="c")
    ]
    assert hash_tasks(swapped) != base


def test_manifest_hash_excludes_timestamp():
    tasks, report = _tasks(), _report()
    m1 = build_manifest("s", tasks, report, timestamp="2026-01-01T00:00:00Z")
    m2 = build_manifest("s", tasks, report, timestamp="2026-12-31T23:59:59Z")
    assert m1.manifest_hash == m2.manifest_hash
    assert m1.timestamp != m2.timestamp


def test_manifest_hash_changes_with_config_or_score():
    tasks, report = _tasks(), _report()
    base = build_manifest("s", tasks, report).manifest_hash
    diff_cfg = build_manifest(
        "s", tasks, report, config=RunConfig(model="gpt-4o", temperature=0.7)
    ).manifest_hash
    diff_score = build_manifest("s", tasks, _report(solved=2)).manifest_hash
    assert diff_cfg != base
    assert diff_score != base


def test_manifest_roundtrips_json():
    m = build_manifest("s", _tasks(), _report())
    assert '"manifest_hash"' in m.to_json()
    assert m.pass_at_1 == 0.5
