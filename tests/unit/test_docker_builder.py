"""Tests for the bench Docker builder (graceful, mocked subprocess)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.bench.docker_builder import DockerBuilder, RunningTarget
from cyberai.bench.targets import LOCAL_SUITE


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
    with patch.object(b, "_run", return_value=fake):
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
