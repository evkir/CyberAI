"""Tests for the bench Docker builder (graceful, mocked subprocess)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.bench.docker_builder import DockerBuilder, RunningTarget
from cyberai.bench.targets import LOCAL_SUITE


@patch("cyberai.bench.docker_builder.run_sealed")
def test_run_uses_sealed_exec(mock_run):
    """The docker CLI must not inherit the operator environment."""
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    DockerBuilder()._run(["ps"])
    argv = mock_run.call_args.args[0]
    assert argv[0] == "docker"
    kwargs = mock_run.call_args.kwargs
    assert "home" not in kwargs  # synthetic home, not the operator's
    assert "capture_output" not in kwargs  # run_sealed applies it itself


@patch("cyberai.bench.docker_builder.shutil.which", return_value=None)
def test_unavailable_without_docker(_which):
    b = DockerBuilder()
    assert b.available is False
    assert b.start(LOCAL_SUITE[0]) is None


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_available_with_docker(_which):
    assert DockerBuilder().available is True


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_start_returns_handle_on_success(_which):
    b = DockerBuilder()
    fake = MagicMock(returncode=0, stdout="abc123\n", stderr="")
    with (
        patch.object(b, "_run", return_value=fake),
        patch.object(DockerBuilder, "_wait_ready", return_value=True),
    ):
        running = b.start(LOCAL_SUITE[0])
    assert isinstance(running, RunningTarget)
    assert running.container_id == "abc123"
    assert running.base_url.startswith("http://localhost:")


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_start_returns_none_on_nonzero(_which):
    b = DockerBuilder()
    fake = MagicMock(returncode=1, stdout="", stderr="boom")
    with patch.object(b, "_run", return_value=fake):
        assert b.start(LOCAL_SUITE[0]) is None


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_stop_success(_which):
    b = DockerBuilder()
    running = RunningTarget("x", "cid", "http://localhost:8801")
    with patch.object(b, "_run", return_value=MagicMock(returncode=0)):
        assert b.stop(running) is True


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_start_launches_the_app_module(_which):
    """The container must run our app, not idle — this was the 0% bench bug."""
    b = DockerBuilder()
    fake = MagicMock(returncode=0, stdout="abc123\n", stderr="")
    target = LOCAL_SUITE[0]
    with (
        patch.object(b, "_run", return_value=fake) as run,
        patch.object(DockerBuilder, "_wait_ready", return_value=True),
    ):
        b.start(target)
    args = run.call_args[0][0]
    assert "sleep" not in args
    assert f"/apps/{target.app}.py" in args
    assert str(target.port) in args
    assert any(arg.endswith("/apps:ro") for arg in args)


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_start_stops_container_when_never_ready(_which):
    b = DockerBuilder()
    fake = MagicMock(returncode=0, stdout="abc123\n", stderr="")
    with (
        patch.object(b, "_run", return_value=fake),
        patch.object(DockerBuilder, "_wait_ready", return_value=False),
        patch.object(DockerBuilder, "stop", return_value=True) as stop,
    ):
        assert b.start(LOCAL_SUITE[0]) is None
    stop.assert_called_once()
