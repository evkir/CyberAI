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

from cyberai.agents.exploit.web_payloads import WebVulnClass
from cyberai.bench.agent_engine import AttackOutcome, agent_attack, make_agent_runner
from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.runner import BenchTask
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
        attacker=kw.get("attacker", lambda url, task: outcome),
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
    def _explode(url, task):
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
        attacker=lambda url, task: AttackOutcome(confirmed=0),
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


def test_agent_attack_reads_flags_from_the_environment(monkeypatch):
    """Env flags must reach the bench: a config built from defaults pinned
    every new capability to off, and the run reported the pipeline missing
    what it was never allowed to try."""
    monkeypatch.setenv("CYBERAI_USE_API_DISCOVERY", "1")
    seen = {}

    class _Recon:
        def __init__(self, cfg, session):
            seen["cfg"] = cfg
            # BaseAgent assigns this on every agent, so a double without it is
            # not standing in for one. Left off, the caller reading it has to
            # guess an answer instead of measuring it.
            self.llm = None

        def _run_web_recon(self, base_url):
            return {}

    class _Exploit:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_exploit(self, base_url, classes=None):
            return {}

    monkeypatch.setattr("cyberai.bench.agent_engine.ReconAgent", _Recon)
    monkeypatch.setattr("cyberai.bench.agent_engine.ExploitAgent", _Exploit)

    agent_attack("http://t")
    assert seen["cfg"].use_api_discovery is True


def test_agent_attack_forces_the_web_path_on(monkeypatch):
    monkeypatch.delenv("CYBERAI_USE_WEB_RECON", raising=False)
    monkeypatch.delenv("CYBERAI_USE_WEB_EXPLOIT", raising=False)
    monkeypatch.delenv("CYBERAI_USE_OOB", raising=False)
    seen = {}

    class _Recon:
        def __init__(self, cfg, session):
            seen["cfg"] = cfg
            self.llm = None

        def _run_web_recon(self, base_url):
            return {}

    class _Exploit:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_exploit(self, base_url, classes=None):
            return {}

    monkeypatch.setattr("cyberai.bench.agent_engine.ReconAgent", _Recon)
    monkeypatch.setattr("cyberai.bench.agent_engine.ExploitAgent", _Exploit)

    agent_attack("http://t")
    assert seen["cfg"].use_web_recon is True
    assert seen["cfg"].use_web_exploit is True
    # A blind target is unscoreable without this one: the agent confirms it
    # out of band or fails a task it actually solved.
    assert seen["cfg"].use_oob is True


def test_out_of_band_confirmation_counts_as_solved():
    """A blind vector proves itself off the wire or not at all.

    The local SSRF target answers identically whichever way it goes, so its
    declared success signal is a callback, never a response body. A criterion
    that reads only in-band proofs scores it unsolvable for the agent while the
    probe solves it every run, and the gap is logged as a pipeline miss.
    """
    assert AttackOutcome(confirmed=0, oob_confirmed=1).solved is True
    assert AttackOutcome(confirmed=0, oob_confirmed=0).solved is False


def test_agent_attack_carries_the_out_of_band_count_out_of_the_report(monkeypatch):
    """The exploit report counts confirmed callbacks; the outcome must read it.

    params_oob_confirmed was produced by the exploit walk and consumed by
    nobody on this path: the field existed, the callback landed, and the bench
    still recorded an unsolved target.
    """

    class _Recon:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_recon(self, base_url):
            return {}

    class _Exploit:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_exploit(self, base_url, classes=None):
            return {
                "confirmed": 0,
                "endpoints_tested": 1,
                "requests_sent": 10,
                "findings": [],
                "params_oob_confirmed": 1,
            }

    monkeypatch.setattr("cyberai.bench.agent_engine.ReconAgent", _Recon)
    monkeypatch.setattr("cyberai.bench.agent_engine.ExploitAgent", _Exploit)
    outcome = agent_attack("http://t")
    assert outcome.oob_confirmed == 1
    assert outcome.requests_sent == 10
    assert outcome.solved is True


def _recording_agents(monkeypatch):
    """Patch both agents and return the list the exploit call records into."""
    seen: list = []

    class _Recon:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_recon(self, base_url):
            return {}

    class _Exploit:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_exploit(self, base_url, classes=None):
            seen.append(classes)
            return {}

    monkeypatch.setattr("cyberai.bench.agent_engine.ReconAgent", _Recon)
    monkeypatch.setattr("cyberai.bench.agent_engine.ExploitAgent", _Exploit)
    return seen


def _task_describing(description: str) -> BenchTask:
    return BenchTask(
        id="CVE-2024-0001",
        suite="cve-bench",
        target="http://t",
        metadata={"one_day_description": description},
    )


def test_a_zero_day_run_never_reads_the_description(monkeypatch):
    seen = _recording_agents(monkeypatch)

    agent_attack("http://t", _task_describing("A SQL injection flaw in the login form."))

    # The description travels with every task once the loader keeps it. Reading
    # it whenever it is present would rewrite what past zero-day scores meant.
    assert seen == [None]


def test_a_one_day_run_leads_with_the_class_the_description_names(monkeypatch):
    seen = _recording_agents(monkeypatch)

    agent_attack(
        "http://t",
        _task_describing("The plugin is vulnerable to path traversal in the file parameter."),
        one_day=True,
    )

    assert seen[0] is not None
    assert seen[0][0] is WebVulnClass.PATH_TRAVERSAL


def test_one_day_without_a_description_changes_nothing(monkeypatch):
    seen = _recording_agents(monkeypatch)

    # Local-suite tasks carry no description; asking for the mode there is not
    # an error, it simply has nothing to say.
    agent_attack("http://t", _task_describing(""), one_day=True)

    assert seen == [None]


def test_the_real_path_reports_a_zero_it_can_prove(live_sqli_app):
    """Both agents are constructed with two positional arguments, so neither
    is handed a client and no model can be reached. The count is zero because
    the path cannot call one, and the reason names that rather than the
    absent API key -- the key is absent on every machine and would send a
    reader after a knob that changes nothing here."""
    outcome = agent_attack(live_sqli_app)

    assert outcome.llm_calls == 0
    assert outcome.llm_zero_reason == "engine_uses_no_model"


def test_a_client_on_the_path_makes_the_count_unmeasured(monkeypatch):
    """A zero is only publishable while nothing could have been called. Give
    an agent a client and there is still no tracker here to count with, so
    the honest answer becomes absent rather than zero."""

    class _Recon:
        def __init__(self, cfg, session):
            self.llm = object()

        def _run_web_recon(self, base_url):
            return {}

    class _Exploit:
        def __init__(self, cfg, session):
            self.llm = None

        def _run_web_exploit(self, base_url, classes=None):
            return {}

    monkeypatch.setattr("cyberai.bench.agent_engine.ReconAgent", _Recon)
    monkeypatch.setattr("cyberai.bench.agent_engine.ExploitAgent", _Exploit)

    outcome = agent_attack("http://t")

    assert outcome.llm_calls is None
    assert outcome.llm_zero_reason is None


def test_the_model_fact_reaches_the_result_the_scorecard_reads():
    """A measurement that stops at the attacker is not published. The
    scorecard is built from details, so the fact has to arrive there."""
    adapter = LocalSuiteAdapter()
    run = make_agent_runner(
        adapter,
        builder=_FakeBuilder(),
        attacker=lambda url, task: AttackOutcome(
            confirmed=1, llm_calls=0, llm_zero_reason="engine_uses_no_model"
        ),
        judge=lambda target, url: True,
    )
    result = run(_task(adapter))

    assert result.details["llm_calls"] == 0
    assert result.details["llm_zero_reason"] == "engine_uses_no_model"
