"""
End-to-end wiring of the local bench suite: adapter -> runner -> evaluator.

Proves the Day-2 contract holds together without touching Docker or an LLM:
a mocked engine "exploits" a target, the evaluator confirms via the success
marker, and run_suite aggregates an honest pass@1. The mocked engine returns
real success markers for two targets and a benign reply for one, so the suite
must report exactly 2/3 solved.
"""

from __future__ import annotations

from cyberai.bench.evaluator import evaluate
from cyberai.bench.runner import BenchResult, run_suite
from cyberai.bench.targets import LocalSuiteAdapter, VulnClass


# Markers a successful engine run would surface, keyed by vuln class.
_MARKER = "CMDI-TOK-99"
_SECRET = "root:x:0:0:bench-secret"

_FAKE_EVIDENCE = {
    VulnClass.SQLI: ("FLAG{sqli-auth-bypass}", ""),
    VulnClass.COMMAND_INJECTION: (f"PING ok {_MARKER}", _MARKER),
    # path traversal target gets a benign response -> must count as UNSOLVED
    VulnClass.PATH_TRAVERSAL: ("<html>index</html>", _SECRET),
}


def _mock_engine_runner(adapter: LocalSuiteAdapter):
    """Build a TaskRunner that resolves each task to its VulnTarget, pulls the
    canned evidence, and runs it through the real evaluator."""

    def runner(task) -> BenchResult:
        target = adapter.get_target(task.id)
        assert target is not None, f"unknown task {task.id}"
        evidence, marker = _FAKE_EVIDENCE[target.vuln_class]
        solved = evaluate(target, evidence, marker=marker)
        return BenchResult(
            task_id=task.id,
            suite=task.suite,
            solved=solved,
            details={"vuln_class": target.vuln_class.value},
        )

    return runner


def test_local_suite_e2e_pass_at_1_is_two_thirds():
    adapter = LocalSuiteAdapter()
    report = run_suite(adapter, _mock_engine_runner(adapter))

    assert report.suite == "local"
    assert report.total == 3
    assert report.solved == 2
    assert report.pass_at_1 == 2 / 3

    solved_ids = {r.task_id for r in report.results if r.solved}
    assert "local-sqli-login" in solved_ids
    assert "local-cmdi-ping" in solved_ids
    assert "local-path-traversal" not in solved_ids


def test_local_suite_e2e_all_solved_when_engine_succeeds():
    adapter = LocalSuiteAdapter()

    def perfect_runner(task) -> BenchResult:
        # every target yields its success marker -> full solve
        return BenchResult(task_id=task.id, suite=task.suite, solved=True)

    report = run_suite(adapter, perfect_runner)
    assert report.solved == 3
    assert report.pass_at_1 == 1.0
