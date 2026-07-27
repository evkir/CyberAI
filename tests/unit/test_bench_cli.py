"""Tests for the `cyberai bench` CLI (list / run)."""

from __future__ import annotations

from click.testing import CliRunner

from cyberai.cli.bench import bench


def test_bench_list_shows_local_targets():
    result = CliRunner().invoke(bench, ["list"])
    assert result.exit_code == 0
    assert "local" in result.output
    assert "local-sqli-login" in result.output


def test_bench_run_default_suite_exit_zero():
    result = CliRunner().invoke(bench, ["run"])
    assert result.exit_code == 0
    assert "pass@1" in result.output
    # placeholder runner never fakes success -> 0/3
    assert "0/3" in result.output


def test_bench_run_rejects_unknown_suite():
    result = CliRunner().invoke(bench, ["run", "--suite", "nope"])
    assert result.exit_code != 0


def test_bench_run_writes_scorecard(tmp_path):
    from click.testing import CliRunner

    out = tmp_path / "sc.md"
    result = CliRunner().invoke(bench, ["run", "--scorecard", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    text = out.read_text()
    assert "Benchmark Scorecard" in text
    assert "pass@1" in text


def test_bench_list_includes_ctf_suite():
    from click.testing import CliRunner

    result = CliRunner().invoke(bench, ["list"])
    assert result.exit_code == 0
    assert "ctf" in result.output
    assert "Decode the Base" in result.output


def test_bench_run_ctf_suite_exit_zero():
    from click.testing import CliRunner

    result = CliRunner().invoke(bench, ["run", "--suite", "ctf"])
    assert result.exit_code == 0
    assert "pass@1" in result.output


def _stub_agent_runner(details_by_task):
    """Build a make_agent_runner stand-in yielding fixed results."""
    from cyberai.bench.runner import BenchResult

    def _factory(adapter, **kwargs):
        def _run(task):
            details = details_by_task.get(task.id, {})
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=bool(details.get("agent_confirmed")),
                details=details,
            )

        return _run

    return _factory


def test_bench_run_agent_engine_shows_the_probe_beside_the_agent(monkeypatch):
    import cyberai.cli.bench as mod

    details = {
        "local-sqli-login": {"agent_confirmed": 2, "judge_solved": True},
        "local-cmdi-ping": {
            "agent_confirmed": 0,
            "judge_solved": True,
            "disagreement": "probe proved it, agent missed it",
        },
    }
    factory = _stub_agent_runner(details)
    monkeypatch.setitem(mod._LIVE_ENGINES, "agent", factory)

    result = CliRunner().invoke(bench, ["run", "--engine", "agent"])

    assert result.exit_code == 0
    assert "probe" in result.output, "the judge verdict must be visible in the run"
    # An agent miss on an exploitable target is the number worth acting on:
    # it has to reach the operator, not just the JSON.
    assert "disagreement on local-cmdi-ping" in result.output
    assert "1/3" in result.output, "score follows the agent, not the probe"


def test_bench_run_agent_engine_falls_back_off_the_local_suite(monkeypatch):
    import cyberai.cli.bench as mod

    def _boom(adapter, **kwargs):
        raise AssertionError("agent engine must not run without live targets")

    monkeypatch.setitem(mod._LIVE_ENGINES, "agent", _boom)

    result = CliRunner().invoke(bench, ["run", "--suite", "ctf", "--engine", "agent"])

    assert result.exit_code == 0
    assert "local suite only" in result.output
    assert "pass@1" in result.output


def test_bench_run_rejects_unknown_engine():
    result = CliRunner().invoke(bench, ["run", "--engine", "magic"])
    assert result.exit_code != 0
