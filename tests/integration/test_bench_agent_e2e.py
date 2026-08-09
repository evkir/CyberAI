"""
End-to-end for the agent bench engine, with nothing faked but the container.

Every part that decides the number is real here: the vulnerable apps, the agent
web path, the per-class probes. Only the Docker layer is stood in for, because
the point of this test is the verdict logic, not container orchestration -- and
a suite that can only be exercised with Docker up is a suite nobody runs.

The traversal app normally reads a secret planted outside its web root inside
the container. Here that layout is rebuilt in a temp directory so the file the
probe reaches for actually exists: without it the probe would fail closed and
the test would be asserting an artefact of the test environment rather than the
behaviour of the engine.
"""

from __future__ import annotations

import threading
from http.server import HTTPServer

import pytest

from cyberai.bench.agent_engine import make_agent_runner
from cyberai.bench.apps import cmdi_ping, path_traversal, sqli_login
from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.targets import LocalSuiteAdapter

# The response-provable classes only. The blind SSRF target is deliberately
# absent: it answers identically whether or not it issued the outbound request,
# so the response-reading walk drops it by design and no agent verdict here
# could be anything but unsolved. Its proof lives out of band, and asserting it
# in this file would turn a designed behaviour into an apparent failure.
_APPS = {
    "local-sqli-login": sqli_login,
    "local-cmdi-ping": cmdi_ping,
    "local-path-traversal": path_traversal,
}


def _serve(handler_cls) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def traversal_secrets(tmp_path, monkeypatch):
    """Rebuild the container's out-of-web-root layout under a temp directory.

    The web root sits six levels down so both the probe's four-level escape and
    the agent's six-level one land on planted files instead of the real
    filesystem. Nothing outside tmp_path is touched.
    """
    web_root = tmp_path.joinpath("srv", "www", "a", "b", "c", "d")
    web_root.mkdir(parents=True)
    web_root.joinpath("index.html").write_text("bench index\n")

    passwd = "root:x:0:0:root:/root:/bin/sh\n"
    for depth_root in (tmp_path, tmp_path / "srv" / "www"):
        etc = depth_root / "etc"
        etc.mkdir(parents=True, exist_ok=True)
        etc.joinpath("bench_flag").write_text(path_traversal.SECRET_BODY)
        etc.joinpath("passwd").write_text(passwd)

    monkeypatch.setattr(path_traversal, "WEB_ROOT", str(web_root))
    return web_root


@pytest.fixture
def live_suite(traversal_secrets):
    """The response-provable bench apps served in-process, keyed by task id."""
    servers = {tid: _serve(mod.Handler) for tid, mod in _APPS.items()}
    try:
        yield {tid: f"http://127.0.0.1:{s.server_port}" for tid, s in servers.items()}
    finally:
        for s in servers.values():
            s.shutdown()
            s.server_close()


class _InProcessBuilder:
    """Points the runner at the in-process apps instead of containers."""

    def __init__(self, urls: dict[str, str]):
        self.urls = urls
        self.stopped: list[str] = []

    def start(self, target):
        return RunningTarget(
            target_id=target.id, container_id="in-process", base_url=self.urls[target.id]
        )

    def stop(self, running) -> bool:
        self.stopped.append(running.target_id)
        return True


def test_agents_solve_the_local_suite_and_the_probes_concur(live_suite):
    adapter = LocalSuiteAdapter()
    builder = _InProcessBuilder(live_suite)
    run = make_agent_runner(adapter, builder=builder)

    all_tasks = adapter.load_tasks()
    tasks = [t for t in all_tasks if t.id in _APPS]
    # Referenced against the suite, not against _APPS: comparing the filtered
    # list to the thing that filtered it compares a value with itself. A target
    # added to the suite without an app here would silently narrow this test.
    assert {t.id for t in all_tasks} - set(_APPS) == {"local-ssrf-fetch"}, (
        "only the blind SSRF target may be absent from the response-provable set"
    )
    results = [run(task) for task in tasks]

    assert [r.solved for r in results] == [True] * len(_APPS), (
        "the pipeline is expected to prove every response-provable class unaided"
    )
    for r in results:
        assert r.details["agreement"] is True, f"{r.task_id}: agent and probe must concur"
        assert r.details["agent_confirmed"] >= 1
        assert "disagreement" not in r.details
    assert sorted(builder.stopped) == sorted(_APPS), "every target torn down"


def test_every_finding_carries_the_proof_that_earned_it(live_suite):
    adapter = LocalSuiteAdapter()
    run = make_agent_runner(adapter, builder=_InProcessBuilder(live_suite))

    tasks = [t for t in adapter.load_tasks() if t.id in _APPS]
    findings = [f for task in tasks for f in run(task).details["findings"]]

    assert findings
    for f in findings:
        assert f["proof"], "a finding without a proof would be a claim, not evidence"
        assert f["parameter"], "triage needs the parameter that fell"


def test_a_silent_target_is_a_clean_miss_not_a_crash(live_suite):
    """A target that answers nothing must produce an honest unsolved."""
    adapter = LocalSuiteAdapter()
    urls = dict(live_suite)
    urls["local-sqli-login"] = "http://127.0.0.1:1"
    run = make_agent_runner(adapter, builder=_InProcessBuilder(urls))

    task = next(t for t in adapter.load_tasks() if t.id == "local-sqli-login")
    result = run(task)

    assert result.solved is False
    assert result.details["agent_confirmed"] == 0
    assert result.details["judge_solved"] is False
