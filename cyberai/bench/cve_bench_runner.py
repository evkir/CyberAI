"""
Runner for the CVE-Bench suite: our agent attacks, their grader decides.

This inverts the local suite deliberately. There, we author the probes, so the
agent is the thing measured and the probe is a cross-check. Here the grader is
upstream, it runs inside the target, and it reads canaries and secrets the
attacker never sees. That makes it the ground truth, and `solved` is its
verdict — anything else would be us grading our own homework on someone else's
benchmark.

What the agent produced is still recorded. Findings with no credited attack are
the interesting direction: our web exploitation can prove an injection that
none of the eight upstream criteria count, which is a real result about the
scope of the benchmark rather than a score. Recorded, never scored.

A grader that cannot be reached is an error, not a zero. An unreachable grader
and a genuinely unexploited target are different facts, and collapsing them
would quietly deflate every future run.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

import httpx

from cyberai.bench.agent_engine import AttackFn, AttackOutcome, agent_attack
from cyberai.bench.cve_bench import SUITE_NAME, CVEBenchAdapter
from cyberai.bench.cve_bench_driver import CVEBenchSandbox
from cyberai.bench.runner import BenchResult, BenchTask

logger = logging.getLogger("cyberai.bench.cve_bench_runner")

VERDICT_TIMEOUT = 30

# A verdict is (solved, message); solved None means the grader did not answer.
VerdictFn = Callable[[str], tuple[Optional[bool], str]]


def grader_verdict(verdict_url: str, timeout: int = VERDICT_TIMEOUT) -> tuple[Optional[bool], str]:
    """Ask the in-container grader whether the attack succeeded.

    Returns (None, reason) when the grader is unreachable or answers in a shape
    we do not recognise. That is deliberately not False: "we could not ask" and
    "the answer was no" are different facts.
    """
    try:
        response = httpx.get(verdict_url, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return None, f"grader unreachable: {exc}"

    if not isinstance(payload, dict) or not isinstance(payload.get("status"), bool):
        return None, f"unrecognised grader response: {payload!r}"
    return bool(payload["status"]), str(payload.get("message", ""))


def make_cve_bench_runner(
    adapter: CVEBenchAdapter | None = None,
    sandbox: CVEBenchSandbox | None = None,
    attacker: Optional[AttackFn] = None,
    verdict: Optional[VerdictFn] = None,
):
    """Build a TaskRunner for the CVE-Bench suite.

    Everything the runner talks to is injectable, so the verdict logic can be
    exercised without Docker, a checkout, or several gigabytes of images.
    """
    adapter = adapter or CVEBenchAdapter()
    box = sandbox or CVEBenchSandbox(root=adapter.root, version=adapter.version)
    attack = attacker or agent_attack
    ask = verdict or grader_verdict

    def _run(task: BenchTask) -> BenchResult:
        running = box.start(task)
        if running is None:
            return BenchResult(
                task_id=task.id,
                suite=SUITE_NAME,
                solved=False,
                error=box.unavailable_reason or "task did not come up",
                details={"engine": "agent", "cve": task.id, "available": False},
            )

        try:
            outcome = _attack(attack, running.base_url, task.id)
            status, message = ask(task.metadata.get("verdict_url", ""))
            details: dict[str, Any] = {
                "engine": "agent",
                "cve": task.id,
                "available": True,
                "base_url": running.base_url,
                "grader_status": status,
                "grader_message": message,
                "agent_confirmed": outcome.confirmed,
                "endpoints_tested": outcome.endpoints_tested,
                "requests_sent": outcome.requests_sent,
                "findings": outcome.findings,
            }
            if status is None:
                # No verdict means no measurement. Say so instead of scoring it.
                return BenchResult(
                    task_id=task.id,
                    suite=SUITE_NAME,
                    solved=False,
                    error=message,
                    details=details,
                )
            if outcome.confirmed and not status:
                details["uncredited_findings"] = (
                    "the agent proved an injection the grader does not count as "
                    "one of its eight attack criteria"
                )
            return BenchResult(
                task_id=task.id,
                suite=SUITE_NAME,
                solved=status,
                details=details,
            )
        finally:
            box.stop(running)

    return _run


def _attack(attack: AttackFn, base_url: str, task_id: str) -> AttackOutcome:
    """Run the attacker; a crash is an empty outcome, not a dead suite.

    The grader is still asked afterwards: an attack that raised halfway may
    already have triggered a criterion, and that would still be a real solve.
    """
    try:
        return attack(base_url)
    except Exception as exc:  # noqa: BLE001 — one bad target must not stop the rest
        logger.warning("agent errored on %s: %s", task_id, exc)
        return AttackOutcome()
