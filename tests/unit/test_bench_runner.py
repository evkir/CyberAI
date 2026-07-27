"""Tests for the benchmark harness contract (cyberai/bench/runner.py)."""

from __future__ import annotations

import pytest

from cyberai.bench.runner import (
    BenchAdapter,
    BenchResult,
    BenchTask,
    SuiteReport,
    run_suite,
    run_task,
)


class _FakeAdapter(BenchAdapter):
    name = "fake"

    def __init__(self, tasks):
        self._tasks = tasks

    def load_tasks(self):
        return self._tasks


def _task(tid):
    return BenchTask(id=tid, suite="fake", target="example.com")


def test_run_suite_aggregates_pass_at_1():
    adapter = _FakeAdapter([_task("a"), _task("b"), _task("c")])

    def runner(task):
        return BenchResult(task_id=task.id, suite=task.suite, solved=task.id != "c")

    report = run_suite(adapter, runner)
    assert isinstance(report, SuiteReport)
    assert report.total == 3
    assert report.solved == 2
    assert report.pass_at_1 == 2 / 3


def test_run_task_stamps_duration():
    result = run_task(
        _task("x"),
        lambda t: BenchResult(task_id=t.id, suite=t.suite, solved=True),
    )
    assert result.solved is True
    assert result.duration_s >= 0.0


def test_run_task_converts_exception_to_unsolved():
    def boom(task):
        raise ValueError("nope")

    result = run_task(_task("y"), boom)
    assert result.solved is False
    assert result.error is not None
    assert "ValueError" in result.error


def test_pass_at_1_empty_suite_is_zero():
    report = run_suite(
        _FakeAdapter([]),
        lambda t: BenchResult(task_id=t.id, suite=t.suite, solved=True),
    )
    assert report.total == 0
    assert report.pass_at_1 == 0.0


def test_adapter_is_abstract():
    with pytest.raises(TypeError):
        BenchAdapter()


def test_a_preselected_subset_is_the_whole_report():
    """A filtered run must not be reported against the suite's size."""
    adapter = _FakeAdapter([_task("a"), _task("b"), _task("c")])

    def runner(task):
        return BenchResult(task_id=task.id, suite=task.suite, solved=True)

    report = run_suite(adapter, runner, tasks=[_task("b")])

    assert report.total == 1
    assert report.solved == 1
    assert report.pass_at_1 == 1.0
    assert [r.task_id for r in report.results] == ["b"]


def test_an_empty_selection_scores_nothing_rather_than_everything():
    adapter = _FakeAdapter([_task("a"), _task("b")])

    def runner(task):
        raise AssertionError("no task was selected, so none may run")

    report = run_suite(adapter, runner, tasks=[])

    assert report.total == 0
    assert report.pass_at_1 == 0.0
