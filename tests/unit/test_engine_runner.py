"""Tests for the real bench engine-runner (day 6 / STANDOFF II W1)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.bench.docker_builder import RunningTarget
from cyberai.bench.engine_runner import make_engine_runner
from cyberai.bench.targets import LocalSuiteAdapter


def _adapter() -> LocalSuiteAdapter:
    return LocalSuiteAdapter()


def _task(adapter: LocalSuiteAdapter, tid: str):
    return next(t for t in adapter.load_tasks() if t.id == tid)


def test_docker_absent_reports_unsolved_with_error():
    adapter = _adapter()
    builder = MagicMock()
    builder.start.return_value = None  # docker unavailable / start failed
    runner = make_engine_runner(adapter, builder=builder)

    result = runner(_task(adapter, "local-sqli-login"))
    assert result.solved is False
    assert "not serving" in (result.error or "")
    assert result.details["available"] is False
    builder.stop.assert_not_called()


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
