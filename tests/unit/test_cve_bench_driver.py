"""
Tests for the CVE-Bench sandbox driver.

Nothing here starts Docker. What is worth pinning down is the argv handed to
the upstream script, and the cleanup: a task that fails halfway still holds
host ports 9090 and 9091, and if the driver walks away from it every later
task fails for a reason that has nothing to do with the agent.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from cyberai.bench.cve_bench_driver import CVEBenchSandbox
from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.runner import BenchTask

_CVE = "CVE-2024-2624"


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "cve-bench"
    (root / "src" / "critical" / "challenges" / _CVE).mkdir(parents=True)
    (root / "run").write_text("#!/usr/bin/env bash\n")
    return root


@pytest.fixture
def sandbox(checkout):
    with patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"):
        box = CVEBenchSandbox(root=checkout, ready_timeout=0)
        box._compose_ok = True
        # The port probe is the one thing here that would touch the host: a
        # grid on 9090 would otherwise make every start() test fail locally
        # and pass in CI. Tests that care about the probe patch it themselves.
        with patch.object(CVEBenchSandbox, "_port_in_use", return_value=False):
            yield box


def _task() -> BenchTask:
    return BenchTask(id=_CVE, suite="cve-bench", target="http://127.0.0.1:9090")


def _ok(**kw) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=kw.get("rc", 0), stdout="", stderr="")


def test_start_uses_the_upstream_script_without_building(sandbox, checkout):
    with (
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=_ok()) as run,
        patch.object(CVEBenchSandbox, "_wait_healthy", return_value=True),
    ):
        running = sandbox.start(_task())

    assert running is not None
    assert running.base_url == "http://127.0.0.1:9090"
    assert running.container_id == _CVE.lower(), "upstream names the project after the CVE"
    argv, kwargs = run.call_args[0][0], run.call_args[1]
    assert argv == ["./run", "up", _CVE, "--no-build"]
    assert kwargs["cwd"] == str(checkout)
    assert kwargs["extra_env"]["CVEBENCH_VERSION"] == "critical"


def test_building_is_opt_in(checkout):
    with (
        patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"),
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=_ok()) as run,
        patch.object(CVEBenchSandbox, "_wait_healthy", return_value=True),
        # This one builds its own sandbox, so the fixture's stub does not
        # cover it: without this the test asks the host whether 9090 is free
        # and fails whenever a target or a grid is up.
        patch.object(CVEBenchSandbox, "_port_in_use", return_value=False),
    ):
        box = CVEBenchSandbox(root=checkout, build=True, ready_timeout=0)
        box._compose_ok = True
        box.start(_task())

    assert run.call_args[0][0] == ["./run", "up", _CVE]


def test_a_taken_port_is_named_not_blamed_on_the_stack(sandbox):
    """An occupied 9090 must not reach `up` and must not read as a stack failure."""
    with (
        patch("cyberai.bench.cve_bench_driver.run_sealed") as run,
        patch.object(CVEBenchSandbox, "_port_in_use", return_value=True),
    ):
        running = sandbox.start(_task())
    assert running is None
    assert run.call_args_list == [], "up must not be attempted on a taken port"


def test_a_failed_start_is_torn_down_not_abandoned(sandbox):
    failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
    with (
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=failed) as run,
        patch.object(CVEBenchSandbox, "_wait_healthy", return_value=True),
    ):
        running = sandbox.start(_task())

    assert running is None
    assert ["./run", "down", _CVE] in [c[0][0] for c in run.call_args_list], (
        "a half-built stack still holds the published ports"
    )


def test_a_stack_that_never_goes_healthy_is_torn_down(sandbox):
    with (
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=_ok()) as run,
        patch.object(CVEBenchSandbox, "_wait_healthy", return_value=False),
    ):
        running = sandbox.start(_task())

    assert running is None
    assert ["./run", "down", _CVE] in [c[0][0] for c in run.call_args_list]


def test_a_timeout_is_a_teardown_too(sandbox):
    def _side_effect(argv, **kwargs):
        if argv[1] == "up":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=1)
        return _ok()

    with patch("cyberai.bench.cve_bench_driver.run_sealed", side_effect=_side_effect) as run:
        running = sandbox.start(_task())

    assert running is None
    assert ["./run", "down", _CVE] in [c[0][0] for c in run.call_args_list]


def test_stop_reports_failure_honestly(sandbox):
    failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
    running = RunningTarget(target_id=_CVE, container_id=_CVE.lower(), base_url="http://x")
    with patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=failed):
        assert sandbox.stop(running) is False

    with patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=_ok()):
        assert sandbox.stop(running) is True


def test_missing_docker_is_a_skip_not_a_crash(checkout):
    def _which(name):
        return None if name == "docker" else "/usr/bin/uv"

    # Every assertion stays inside the patch: unavailable_reason is recomputed
    # on each access, so outside it this test would only pass on a machine
    # that happens to lack docker.
    with patch("cyberai.bench.cve_bench_driver.shutil.which", side_effect=_which):
        sandbox = CVEBenchSandbox(root=checkout)
        with patch("cyberai.bench.cve_bench_driver.run_sealed") as run:
            assert sandbox.start(_task()) is None
            run.assert_not_called()
        assert "docker" in (sandbox.unavailable_reason or "")


def test_missing_uv_is_reported_because_the_upstream_script_needs_it(checkout):
    def _which(name):
        return None if name == "uv" else "/usr/bin/docker"

    with patch("cyberai.bench.cve_bench_driver.shutil.which", side_effect=_which):
        sandbox = CVEBenchSandbox(root=checkout)

        assert sandbox.available is False
        assert "uv" in (sandbox.unavailable_reason or "")


def test_missing_checkout_is_reported_before_any_tooling(tmp_path):
    sandbox = CVEBenchSandbox(root=tmp_path / "nowhere")

    assert sandbox.available is False
    assert "checkout" in (sandbox.unavailable_reason or "")
    assert sandbox.start(_task()) is None
    assert sandbox.stop(RunningTarget(_CVE, _CVE.lower(), "http://x")) is False


def test_a_missing_compose_plugin_is_caught_before_anything_starts(checkout):
    """The upstream script exits zero when compose fails, so this must be
    checked up front: otherwise every task waits out the readiness timeout
    for a stack that was never built."""
    missing = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
    with (
        patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"),
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=missing) as run,
    ):
        sandbox = CVEBenchSandbox(root=checkout)

        assert sandbox.available is False
        assert "compose" in (sandbox.unavailable_reason or "")
        assert sandbox.start(_task()) is None
        assert ["./run", "up", _CVE, "--no-build"] not in [c[0][0] for c in run.call_args_list]


def test_the_upstream_script_gets_one_variable_not_our_environment(sandbox):
    """The script and its containers must not see the operator's LLM keys."""
    with (
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=_ok()) as run,
        patch.object(CVEBenchSandbox, "_wait_healthy", return_value=True),
    ):
        sandbox.start(_task())

    up = next(c for c in run.call_args_list if c[0][0][:2] == ["./run", "up"])
    assert set(up[1]["extra_env"]) == {"CVEBENCH_VERSION"}
    assert "env" not in up[1]  # no os.environ copy
    assert up[1]["home"] == Path.home()  # uv resolves its cache under ~


def test_the_compose_check_runs_once(checkout):
    probe = subprocess.CompletedProcess(args=[], returncode=0, stdout="v2", stderr="")
    with (
        patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"),
        patch("cyberai.bench.cve_bench_driver.run_sealed", return_value=probe) as run,
    ):
        sandbox = CVEBenchSandbox(root=checkout)
        for _ in range(3):
            assert sandbox.available is True

    compose_calls = [c for c in run.call_args_list if c[0][0][:2] == ["docker", "compose"]]
    assert len(compose_calls) == 1, "availability is polled often; the subprocess is not"


def test_a_docker_that_will_not_run_is_treated_as_no_compose(checkout):
    """Probing the plugin can fail outright, not just answer no.

    A docker binary that is present but unusable -- broken install, daemon
    socket denied, a probe that hangs past its timeout -- must land on the
    same fail-fast path as a missing plugin rather than raise out of an
    availability check.
    """
    for boom in (
        OSError("cannot execute docker"),
        subprocess.TimeoutExpired(cmd=["docker", "compose", "version"], timeout=30),
    ):
        with (
            patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"),
            patch("cyberai.bench.cve_bench_driver.run_sealed", side_effect=boom),
        ):
            sandbox = CVEBenchSandbox(root=checkout)

            assert sandbox.available is False
            assert "compose" in (sandbox.unavailable_reason or "")
            assert sandbox.start(_task()) is None


def test_a_run_script_that_cannot_be_executed_is_not_fatal(sandbox):
    with patch("cyberai.bench.cve_bench_driver.run_sealed", side_effect=OSError("no exec")):
        assert sandbox.start(_task()) is None
        assert sandbox.stop(RunningTarget(_CVE, _CVE.lower(), "http://x")) is False


def test_readiness_waits_for_the_graders_own_health_verdict(checkout):
    """A published port answers before the app behind it does.

    The readiness signal has to be the grader saying the application is
    serving, not a socket Docker opened on its behalf -- getting this wrong is
    what turns a broken stack into a silent timeout per task.
    """
    with patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"):
        sandbox = CVEBenchSandbox(root=checkout, ready_timeout=10)

    responses = [
        httpx.ConnectError("refused"),
        httpx.Response(500, request=httpx.Request("GET", "http://127.0.0.1:9091/health")),
        httpx.Response(200, request=httpx.Request("GET", "http://127.0.0.1:9091/health")),
    ]

    def _get(*args, **kwargs):
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    with (
        patch("cyberai.bench.cve_bench_driver.httpx.get", side_effect=_get),
        patch("cyberai.bench.cve_bench_driver.time.sleep"),
    ):
        assert sandbox._wait_healthy() is True
    assert responses == [], "a refusal and a 500 are both retried, not accepted"


def test_readiness_gives_up_and_says_so(checkout):
    with patch("cyberai.bench.cve_bench_driver.shutil.which", return_value="/usr/bin/x"):
        sandbox = CVEBenchSandbox(root=checkout, ready_timeout=2)

    with (
        patch("cyberai.bench.cve_bench_driver.httpx.get", side_effect=httpx.ConnectError("x")),
        patch("cyberai.bench.cve_bench_driver.time.sleep"),
    ):
        assert sandbox._wait_healthy() is False
