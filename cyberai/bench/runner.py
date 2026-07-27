"""
Benchmark harness — contract layer.

Defines the framework-agnostic types every benchmark suite (CVE-Bench,
CyBench, EVMBench, local) plugs into. No attack logic lives here: an adapter
loads tasks, a runner callable executes CyberAI against one task and returns a
BenchResult, and run_suite aggregates pass@1. Concrete adapters arrive later.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BenchTask:
    """A single benchmark task: a target plus how to judge success."""

    id: str
    suite: str
    target: str
    name: str = ""
    success_criteria: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BenchResult:
    """Outcome of running one task. `solved` is the pass@1 signal."""

    task_id: str
    suite: str
    solved: bool
    duration_s: float = 0.0
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SuiteReport:
    """Aggregated results for one run across a suite."""

    suite: str
    total: int
    solved: int
    results: tuple[BenchResult, ...] = ()

    @property
    def pass_at_1(self) -> float:
        return self.solved / self.total if self.total else 0.0


class BenchAdapter(ABC):
    """Loads tasks for a suite. Concrete adapters (CVE-Bench, ...) subclass this."""

    name: str = "base"

    @abstractmethod
    def load_tasks(self) -> list[BenchTask]:
        """Return the tasks for this suite."""
        raise NotImplementedError


# A runner executes CyberAI against one task. Injected so tests/CI can swap it.
TaskRunner = Callable[[BenchTask], BenchResult]


def run_task(task: BenchTask, runner: TaskRunner) -> BenchResult:
    """Run one task, timing it; any runner exception becomes an unsolved result."""
    start = time.perf_counter()
    try:
        result = runner(task)
    except Exception as exc:
        return BenchResult(
            task_id=task.id,
            suite=task.suite,
            solved=False,
            duration_s=time.perf_counter() - start,
            error=f"{type(exc).__name__}: {exc}",
        )
    if result.duration_s == 0.0:
        result = BenchResult(
            task_id=result.task_id,
            suite=result.suite,
            solved=result.solved,
            duration_s=time.perf_counter() - start,
            error=result.error,
            details=result.details,
        )
    return result


def run_suite(
    adapter: BenchAdapter,
    runner: TaskRunner,
    tasks: Sequence[BenchTask] | None = None,
) -> SuiteReport:
    """Load tasks via the adapter, run each, aggregate into a SuiteReport.

    `tasks` narrows the run to a subset the caller already loaded. The report
    then describes that selection and nothing more, so a caller that filters
    owns saying so: pass@1 over one task is not a result for the suite.
    """
    tasks = adapter.load_tasks() if tasks is None else list(tasks)
    results = tuple(run_task(t, runner) for t in tasks)
    solved = sum(1 for r in results if r.solved)
    return SuiteReport(suite=adapter.name, total=len(results), solved=solved, results=results)
