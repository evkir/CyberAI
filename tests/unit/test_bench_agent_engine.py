"""
Tests for the agent-driven bench engine.

Two things must hold. First, `solved` reports the agent and nothing else: the
judge is a second opinion, never a substitute, or the number would measure the
probes again and quietly stop measuring the product. Second, a disagreement
between attacker and judge has to survive into the result — that is the signal
worth acting on, and averaging it away is exactly how a benchmark starts lying.

The attacker and judge are injected here so both verdicts can be driven
independently. One test runs the real agent path against an in-process bench
app, so the private-method seam the runner depends on cannot rot unnoticed.
"""

from __future__ import annotations

import threading
from http.server import HTTPServer

import pytest

from cyberai.bench.agent_engine import AttackOutcome, agent_attack, make_agent_runner
from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.targets import LocalSuiteAdapter

_SQLI_TASK = "local-sqli-login"


class _FakeBuilder:
    """Docker stand-in: hands back a URL and records teardown."""

    def __init__(self, base_url: str | None = "http://t.local:1"):
        self.base_url = base_url
        self.stopped: list[str] = []

    def start(self, target):
        if self.base_url is None:
            return None
        return RunningTarget(target_id=target.id, container_id="fake", base_url=self.base_url)

    def stop(self, running) -> bool:
        self.stopped.append(running.target_id)
        return True


def _task(adapter: LocalSuiteAdapter, task_id: str = _SQLI_TASK):
    return next(t for t in adapter.load_tasks() if t.id == task_id)


def _runner(builder, confirmed: int = 1, judged: bool = True, **kw):
    adapter = LocalSuiteAdapter()
    outcome = AttackOutcome(confirmed=confirmed, endpoints_tested=1, requests_sent=3)
    run = make_agent_runner(
        adapter,
        builder=builder,
        attacker=kw.get("attacker", lambda url: outcome),
        judge=kw.get("judge", lambda target, url: judged),
    )
    return run, _task(adapter)


def test_agent_verdict_decides_solved_not_the_judge():
    run, task = _runner(_FakeBuilder(), confirmed=1, judged=False)
    result = run(task)

    assert result.solved is True, "the engine measures the agent"
    assert result.details["judge_solved"] is False
    assert result.details["agreement"] is False
    assert result.details["disagreement"] == "agent proved it, probe did not"


def test_agent_miss_is_recorded_even_when_the_target_is_exploitable():
    run, task = _runner(_FakeBuilder(), confirmed=0, judged=True)
    result = run(task)

    assert result.solved is False
    assert result.details["disagreement"] == "probe proved it, agent missed it"


def test_agreement_carries_no_disagreement_note():
    run, task = _runner(_FakeBuilder(), confirmed=2, judged=True)
    result = run(task)

    assert result.solved is True
    assert result.details["agreement"] is True
    assert "disagreement" not in result.details
    assert result.details["agent_confirmed"] == 2
    assert result.details["engine"] == "agent"


def test_broken_judge_is_unknown_not_a_clean_bill_of_health():
    def _explode(target, url):
        raise RuntimeError("probe blew up")

    run, task = _runner(_FakeBuilder(), judge=_explode)
    result = run(task)

    assert result.solved is True
    assert result.details["judge_solved"] is None
    assert result.details["agreement"] is None


def test_target_that_never_starts_is_unsolved_not_skipped():
    run, task = _runner(_FakeBuilder(base_url=None))
    result = run(task)

    assert result.solved is False
    assert result.details["available"] is False
    assert "docker unavailable" in (result.error or "")


def test_unknown_task_id_reports_an_error():
    adapter = LocalSuiteAdapter()
    run = make_agent_runner(adapter, builder=_FakeBuilder())
    from cyberai.bench.runner import BenchTask

    result = run(BenchTask(id="nope", suite="local", target="http://x"))

    assert result.solved is False
    assert "no VulnTarget" in (result.error or "")


def test_attacker_failure_is_contained_and_the_target_torn_down():
    def _explode(url):
        raise RuntimeError("agent crashed")

    builder = _FakeBuilder()
    run, task = _runner(builder, attacker=_explode)
    result = run(task)

    assert result.solved is False
    assert "agent crashed" in (result.error or "")
    assert builder.stopped == [_SQLI_TASK], "a crash must not leak a container"


def test_container_is_stopped_after_a_normal_run():
    builder = _FakeBuilder()
    run, task = _runner(builder)
    run(task)

    assert builder.stopped == [_SQLI_TASK]


def test_default_judge_is_the_live_probe():
    # No judge injected: the real probe runs against an unreachable URL and
    # fails closed, which is the honest answer for a target it cannot reach.
    adapter = LocalSuiteAdapter()
    run = make_agent_runner(
        adapter,
        builder=_FakeBuilder(base_url="http://127.0.0.1:1"),
        attacker=lambda url: AttackOutcome(confirmed=0),
    )
    result = run(_task(adapter))

    assert result.details["judge_solved"] is False


@pytest.fixture
def live_sqli_app():
    """Serve the real SQLi bench app in-process on an ephemeral port."""
    from cyberai.bench.apps import sqli_login

    server = HTTPServer(("127.0.0.1", 0), sqli_login.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_agent_attack_drives_both_agents_through_one_session(live_sqli_app):
    outcome = agent_attack(live_sqli_app)

    assert outcome.solved, "recon must hand the surface to exploit through the KB"
    assert outcome.endpoints_tested >= 1
    assert all(f["vuln_class"] == "sqli" for f in outcome.findings)
    assert all(f["proof"] for f in outcome.findings), "a finding without a proof is a guess"
