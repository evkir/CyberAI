"""Tests for the real bench engine-runner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.engine_runner import make_engine_runner
from cyberai.bench.targets import LocalSuiteAdapter


def _adapter() -> LocalSuiteAdapter:
    return LocalSuiteAdapter()


def _task(adapter: LocalSuiteAdapter, tid: str):
    return next(t for t in adapter.load_tasks() if t.id == tid)


def test_docker_absent_reports_unsolved_with_the_reason():
    """The reason the builder recorded is the reason the result carries.

    MagicMock answers every attribute, so a double left to its defaults
    hands the runner a Mock where a sentence belongs and its repr reaches
    the scorecard. The previous assertion read a substring that survived
    that, which is why last_failure is set here and compared whole.
    """
    adapter = _adapter()
    builder = MagicMock()
    builder.start.return_value = None
    builder.last_failure = "docker is not on PATH"
    runner = make_engine_runner(adapter, builder=builder)

    result = runner(_task(adapter, "local-sqli-login"))
    assert result.solved is False
    assert result.error == "target not serving: docker is not on PATH"
    assert result.details["available"] is False
    builder.stop.assert_not_called()


def test_a_builder_that_cannot_say_why_still_reports_a_sentence():
    """The fallback branch, pinned so it cannot start emitting an object.

    last_failure is None on a builder that was never asked, and the result
    has to read as prose either way: a scorecard cell holding the repr of
    whatever the attribute returned is worse than one holding less.
    """
    adapter = _adapter()
    builder = MagicMock()
    builder.start.return_value = None
    builder.last_failure = None
    runner = make_engine_runner(adapter, builder=builder)

    result = runner(_task(adapter, "local-sqli-login"))
    assert result.error == "target not serving"


def test_unknown_task_id_unsolved():
    adapter = _adapter()
    builder = MagicMock()
    runner = make_engine_runner(adapter, builder=builder)

    # A task whose id the local adapter cannot resolve.
    from cyberai.bench.runner import BenchTask

    bogus = BenchTask(id="not-a-local-target", suite="local", target="http://x")
    result = runner(bogus)
    assert result.solved is False
    assert "no VulnTarget" in (result.error or "")
    builder.start.assert_not_called()


def test_live_probe_solved_path():
    adapter = _adapter()
    builder = MagicMock()
    builder.start.return_value = RunningTarget(
        target_id="local-sqli-login",
        container_id="cid",
        base_url="http://localhost:8801",
    )
    runner = make_engine_runner(adapter, builder=builder)

    with patch("cyberai.bench.engine_runner.probe_for", return_value=True):
        result = runner(_task(adapter, "local-sqli-login"))

    assert result.solved is True
    assert result.details["available"] is True
    assert result.details["base_url"] == "http://localhost:8801"
    builder.stop.assert_called_once()


def test_live_probe_unsolved_path():
    adapter = _adapter()
    builder = MagicMock()
    builder.start.return_value = RunningTarget(
        target_id="local-cmdi-ping",
        container_id="cid",
        base_url="http://localhost:8802",
    )
    runner = make_engine_runner(adapter, builder=builder)

    with patch("cyberai.bench.engine_runner.probe_for", return_value=False):
        result = runner(_task(adapter, "local-cmdi-ping"))

    assert result.solved is False
    assert result.error is None
    builder.stop.assert_called_once()


def test_probe_exception_is_caught_and_stops_target():
    adapter = _adapter()
    builder = MagicMock()
    builder.start.return_value = RunningTarget(
        target_id="local-path-traversal",
        container_id="cid",
        base_url="http://localhost:8803",
    )
    runner = make_engine_runner(adapter, builder=builder)

    with patch("cyberai.bench.engine_runner.probe_for", side_effect=RuntimeError("boom")):
        result = runner(_task(adapter, "local-path-traversal"))

    assert result.solved is False
    assert "boom" in (result.error or "")
    builder.stop.assert_called_once()
