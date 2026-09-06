"""
Real engine runner for the local suite.

Replaces the placeholder runner with an honest, reproducible measurement: for
each local task we bring the target up (Docker, when available), run our live
per-class probe against it, judge with the evaluator, and tear the target down.

Honesty contract (the whole point of W1):
  - No fake success. A task is solved ONLY when the live probe extracts the
    unambiguous success signal from a responding target.
  - When Docker is absent, or the vulnerable app is not actually serving on its
    port, every probe fails closed and the task is reported unsolved with a
    concrete `error` — never an overstated solve.
  - A probe may only look for a signal that is absent from its own request, so
    a target reflecting input back cannot be mistaken for an exploited one.
    `tests/unit/test_bench_negative_control.py` holds that line.
  - Probes are fixed exploit checks, not the agent pipeline: this runner
    measures whether the targets are exploitable and the harness is sound.
    Agent-driven measurement is a separate engine mode.

The docker builder mounts `cyberai/bench/apps` read-only into a stock Python
image and runs the app directly, so no per-app Dockerfile is involved. Scope:
`local` suite only — it owns get_target(); CTF has no live target.
"""

from __future__ import annotations

import logging
from typing import Optional

from cyberai.bench.docker_builder import DockerBuilder
from cyberai.bench.evaluator import probe_for
from cyberai.bench.runner import BenchResult, BenchTask, TaskRunner
from cyberai.bench.targets import LocalSuiteAdapter

logger = logging.getLogger(__name__)


def make_engine_runner(
    adapter: LocalSuiteAdapter,
    builder: Optional[DockerBuilder] = None,
) -> TaskRunner:
    """Build a TaskRunner closure over a local adapter and a docker builder.

    The returned callable matches runner.TaskRunner: BenchTask -> BenchResult.
    """
    builder = builder or DockerBuilder()

    def _run(task: BenchTask) -> BenchResult:
        target = adapter.get_target(task.id)
        if target is None:
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=False,
                error="no VulnTarget for task id (local suite only)",
                details={"engine": "real"},
            )

        running = builder.start(target)
        if running is None:
            # Docker absent or start failed — honest unsolved, not a fake pass.
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=False,
                error="target not serving (docker unavailable or start failed)",
                details={
                    "engine": "real",
                    "vuln_class": target.vuln_class.value,
                    "available": False,
                },
            )

        try:
            solved = probe_for(target, running.base_url)
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=solved,
                details={
                    "engine": "real",
                    "vuln_class": target.vuln_class.value,
                    "base_url": running.base_url,
                    "available": True,
                },
            )
        except Exception as exc:  # noqa: BLE001 — one bad target must not kill the suite
            logger.warning("engine runner error on %s: %s", task.id, exc)
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=False,
                error=str(exc),
                details={"engine": "real", "vuln_class": target.vuln_class.value},
            )
        finally:
            builder.stop(running)

    return _run
