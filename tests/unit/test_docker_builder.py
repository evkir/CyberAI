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


@patch("cyberai.bench.docker_builder.shutil.which", return_value=None)
def test_a_missing_docker_says_so_rather_than_nothing(_which):
    b = DockerBuilder()
    assert b.start(LOCAL_SUITE[0]) is None
    assert b.last_failure == "docker is not on PATH"


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_a_refused_run_carries_the_code_and_what_docker_printed(_which):
    b = DockerBuilder()
    fake = MagicMock(returncode=125, stdout="", stderr="  port is already allocated\n")
    with patch.object(b, "_run", return_value=fake):
        assert b.start(LOCAL_SUITE[0]) is None
    assert b.last_failure == "docker run exited 125: port is already allocated"


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_a_raising_run_names_the_exception(_which):
    b = DockerBuilder()
    with patch.object(b, "_run", side_effect=OSError("no such file")):
        assert b.start(LOCAL_SUITE[0]) is None
    assert b.last_failure == "docker run raised OSError: no such file"


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_a_container_that_never_answers_is_not_a_missing_docker(_which):
    """Four facts used to leave this class as one None.

    This is the end of the branch furthest from "docker is absent": the
    daemon ran, the container started, and the application inside it never
    answered. A reader deciding whether a zero belongs to the pipeline needs
    those apart, so the assertion is on the whole sentence and on the absence
    of the word that would make it read as the other one.
    """
    target = LOCAL_SUITE[0]
    b = DockerBuilder()
    fake = MagicMock(returncode=0, stdout="abc123\n", stderr="")
    with (
        patch.object(b, "_run", return_value=fake),
        patch.object(DockerBuilder, "_wait_ready", return_value=False),
        patch.object(DockerBuilder, "stop", return_value=True),
    ):
        assert b.start(target) is None
    assert b.last_failure == f"container started but never answered on port {target.port}"
    assert "docker" not in b.last_failure


@patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker")
def test_a_start_that_works_clears_what_the_last_one_recorded(_which):
    """Otherwise the reason outlives the failure and the next result quotes it."""
    b = DockerBuilder()
    with patch.object(b, "_run", side_effect=OSError("transient")):
        b.start(LOCAL_SUITE[0])
    assert b.last_failure is not None

    fake = MagicMock(returncode=0, stdout="abc123\n", stderr="")
    with (
        patch.object(b, "_run", return_value=fake),
        patch.object(DockerBuilder, "_wait_ready", return_value=True),
    ):
        assert isinstance(b.start(LOCAL_SUITE[0]), RunningTarget)
    assert b.last_failure is None


def test_the_four_ways_to_fail_do_not_share_a_sentence():
    """A guard on the set, not on four strings read one at a time.

    Each assertion above pins its own branch and all four would stay green
    if two of them were made identical; what this change exists to remove is
    exactly that collapse.
    """
    target = LOCAL_SUITE[0]
    reasons = []

    with patch("cyberai.bench.docker_builder.shutil.which", return_value=None):
        b = DockerBuilder()
        b.start(target)
        reasons.append(b.last_failure)

    with patch("cyberai.bench.docker_builder.shutil.which", return_value="/usr/bin/docker"):
        b = DockerBuilder()
        with patch.object(b, "_run", side_effect=OSError("boom")):
            b.start(target)
        reasons.append(b.last_failure)

        b = DockerBuilder()
        with patch.object(b, "_run", return_value=MagicMock(returncode=1, stdout="", stderr="no")):
            b.start(target)
        reasons.append(b.last_failure)

        b = DockerBuilder()
        fake = MagicMock(returncode=0, stdout="abc\n", stderr="")
        with (
            patch.object(b, "_run", return_value=fake),
            patch.object(DockerBuilder, "_wait_ready", return_value=False),
            patch.object(DockerBuilder, "stop", return_value=True),
        ):
            b.start(target)
        reasons.append(b.last_failure)

    assert all(reasons), f"a branch left the reason unset: {reasons}"
    assert len(set(reasons)) == 4, f"two branches share a sentence: {reasons}"
