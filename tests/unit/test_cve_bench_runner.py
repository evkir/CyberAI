"""
Tests for the CVE-Bench runner.

The distinction under test is between "the answer was no" and "we could not
ask". Both look like a zero in a scorecard, and only one of them is a
measurement; a runner that folds the second into the first deflates every run
it appears in without leaving a trace.

The second concern is scoring authority. Upstream owns the grader here, so our
agent's own verdict must never move `solved`, however confident it is.
"""

from __future__ import annotations

import httpx
import pytest

from cyberai.bench.agent_engine import AttackOutcome
from cyberai.bench.cve_bench_runner import grader_verdict, make_cve_bench_runner
from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.runner import BenchTask

_CVE = "CVE-2024-2624"
_VERDICT_URL = "http://127.0.0.1:9091/done"


def _task() -> BenchTask:
    return BenchTask(
        id=_CVE,
        suite="cve-bench",
        target="http://127.0.0.1:9090",
        metadata={"verdict_url": _VERDICT_URL},
    )


class _FakeSandbox:
    def __init__(self, up: bool = True):
        self.up = up
        self.stopped: list[str] = []
        self.unavailable_reason = None if up else "docker is not on PATH"

    def start(self, task):
        if not self.up:
            return None
        return RunningTarget(task.id, task.id.lower(), "http://127.0.0.1:9090")

    def stop(self, running) -> bool:
        self.stopped.append(running.target_id)
        return True


def _runner(sandbox, confirmed=0, status=True, message="File access successful"):
    return make_cve_bench_runner(
        adapter=object(),
        sandbox=sandbox,
        attacker=lambda url, task: AttackOutcome(confirmed=confirmed, endpoints_tested=1),
        verdict=lambda url: (status, message),
    )


def test_the_upstream_grader_decides_the_score():
    result = _runner(_FakeSandbox(), confirmed=0, status=True)(_task())

    assert result.solved is True, "their grader saw a criterion met; our count is irrelevant"
    assert result.details["agent_confirmed"] == 0
    assert result.details["grader_message"] == "File access successful"


def test_agent_findings_never_move_the_score():
    result = _runner(_FakeSandbox(), confirmed=3, status=False, message="Attack unsuccessful")(
        _task()
    )

    assert result.solved is False
    assert result.details["agent_confirmed"] == 3
    assert "uncredited_findings" in result.details, (
        "an injection outside the eight criteria is a result worth recording"
    )


def test_a_credited_solve_carries_no_uncredited_note():
    result = _runner(_FakeSandbox(), confirmed=2, status=True)(_task())

    assert result.solved is True
    assert "uncredited_findings" not in result.details


def test_an_unreachable_grader_is_an_error_not_a_zero():
    runner = make_cve_bench_runner(
        adapter=object(),
        sandbox=_FakeSandbox(),
        attacker=lambda url, task: AttackOutcome(confirmed=1),
        verdict=lambda url: (None, "grader unreachable: connection refused"),
    )

    result = runner(_task())

    assert result.solved is False
    assert "unreachable" in (result.error or ""), "an unmeasured task must not read as measured"
    assert result.details["grader_status"] is None


def test_a_task_that_never_starts_reports_why():
    sandbox = _FakeSandbox(up=False)
    result = _runner(sandbox)(_task())

    assert result.solved is False
    assert "docker" in (result.error or "")
    assert result.details["available"] is False
    assert sandbox.stopped == [], "nothing was started, so nothing to tear down"


def test_the_grader_is_still_asked_after_the_agent_crashes():
    def _explode(url, task):
        raise RuntimeError("agent blew up")

    runner = make_cve_bench_runner(
        adapter=object(),
        sandbox=_FakeSandbox(),
        attacker=_explode,
        verdict=lambda url: (True, "Denial of service successful"),
    )

    result = runner(_task())

    # A crash halfway can still have tripped a criterion; that is a real solve.
    assert result.solved is True
    assert result.details["agent_confirmed"] == 0


def test_the_stack_is_always_torn_down():
    sandbox = _FakeSandbox()
    _runner(sandbox)(_task())

    assert sandbox.stopped == [_CVE]


def _answer(payload) -> httpx.Response:
    """A response the way httpx builds one, with its request attached."""
    return httpx.Response(200, json=payload, request=httpx.Request("GET", _VERDICT_URL))


@pytest.mark.parametrize(
    "payload",
    [
        {"message": "no status field"},
        {"status": "true"},
        ["not", "a", "mapping"],
    ],
)
def test_an_unrecognised_grader_answer_is_not_guessed(payload, monkeypatch):
    monkeypatch.setattr(
        "cyberai.bench.cve_bench_runner.httpx.get",
        lambda *a, **kw: _answer(payload),
    )

    status, message = grader_verdict(_VERDICT_URL)

    assert status is None
    assert "unrecognised" in message


def test_a_transport_failure_is_reported_not_swallowed(monkeypatch):
    def _boom(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("cyberai.bench.cve_bench_runner.httpx.get", _boom)

    status, message = grader_verdict(_VERDICT_URL)

    assert status is None
    assert "unreachable" in message


def test_a_real_verdict_round_trips(monkeypatch):
    monkeypatch.setattr(
        "cyberai.bench.cve_bench_runner.httpx.get",
        lambda *a, **kw: _answer({"status": False, "message": "Attack unsuccessful"}),
    )

    assert grader_verdict(_VERDICT_URL) == (False, "Attack unsuccessful")


def test_a_credited_solve_round_trips(monkeypatch):
    monkeypatch.setattr(
        "cyberai.bench.cve_bench_runner.httpx.get",
        lambda *a, **kw: _answer({"status": True, "message": "Remote code execution successful"}),
    )

    status, message = grader_verdict(_VERDICT_URL)

    assert status is True
    assert "Remote code execution" in message


def test_an_error_status_from_the_grader_is_not_a_verdict(monkeypatch):
    monkeypatch.setattr(
        "cyberai.bench.cve_bench_runner.httpx.get",
        lambda *a, **kw: httpx.Response(500, request=httpx.Request("GET", _VERDICT_URL)),
    )

    status, message = grader_verdict(_VERDICT_URL)

    assert status is None
    assert "unreachable" in message


def test_the_attacker_is_handed_the_task_it_is_attacking():
    """The task carries what the target is: which CVE, and what counts as a win.

    Without it the agent works blind against a benchmark that publishes both,
    and a zero cannot be told apart from a zero it was never equipped to avoid.
    """
    seen: list[BenchTask] = []

    def _record(url, task):
        seen.append(task)
        return AttackOutcome(confirmed=0)

    runner = make_cve_bench_runner(
        adapter=object(),
        sandbox=_FakeSandbox(),
        attacker=_record,
        verdict=lambda url: (False, "Attack unsuccessful"),
    )
    task = _task()
    runner(task)

    assert seen == [task], "the runner must hand the attacker the task, not just a URL"
    assert seen[0].metadata["verdict_url"] == _VERDICT_URL


def test_the_mode_is_on_the_record_in_both_directions():
    """A score whose mode is not recorded cannot be compared to itself later."""
    attacker = lambda url, task: AttackOutcome()  # noqa: E731

    def _build(one_day):
        return make_cve_bench_runner(
            adapter=object(),
            sandbox=_FakeSandbox(),
            attacker=attacker,
            verdict=lambda url: (False, "Attack unsuccessful"),
            one_day=one_day,
        )

    assert _build(False)(_task()).details["mode"] == "zero-day"
    assert _build(True)(_task()).details["mode"] == "one-day"


def test_the_default_runner_attacks_without_the_description(monkeypatch):
    """The published zero-day number has to stay reproducible by default."""
    seen: list = []

    def _spy(base_url, task, one_day=False):
        seen.append(one_day)
        return AttackOutcome()

    monkeypatch.setattr("cyberai.bench.cve_bench_runner.agent_attack", _spy)
    make_cve_bench_runner(
        adapter=object(),
        sandbox=_FakeSandbox(),
        verdict=lambda url: (False, "Attack unsuccessful"),
    )(_task())

    assert seen == [False]


def test_a_one_day_runner_says_so_to_the_attacker(monkeypatch):
    seen: list = []

    def _spy(base_url, task, one_day=False):
        seen.append(one_day)
        return AttackOutcome()

    monkeypatch.setattr("cyberai.bench.cve_bench_runner.agent_attack", _spy)
    make_cve_bench_runner(
        adapter=object(),
        sandbox=_FakeSandbox(),
        verdict=lambda url: (False, "Attack unsuccessful"),
        one_day=True,
    )(_task())

    assert seen == [True]


def test_the_model_fact_travels_on_the_cve_path_too():
    """cve-bench routes through the same attacker, so the same fact has to
    reach its result: two runners publishing one measurement differently is
    how one number becomes two."""
    runner = make_cve_bench_runner(
        adapter=object(),
        sandbox=_FakeSandbox(),
        attacker=lambda url, task: AttackOutcome(
            confirmed=0, llm_calls=0, llm_zero_reason="engine_uses_no_model"
        ),
        verdict=lambda url: (False, "Attack unsuccessful"),
    )

    result = runner(_task())

    assert result.details["llm_calls"] == 0
    assert result.details["llm_zero_reason"] == "engine_uses_no_model"
