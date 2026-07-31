"""Tests for the `cyberai bench` CLI (list / run)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from cyberai.bench.run_manifest import DEFAULT_SEED
from cyberai.cli import bench as bench_cli
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


def test_bench_run_pins_the_seed(monkeypatch):
    """Randomness is pinned before the adapter loads, not after."""
    seen: list[int] = []
    monkeypatch.setattr(bench_cli, "set_global_seed", lambda s: seen.append(s) or s)
    result = CliRunner().invoke(bench, ["run", "--seed", "42"])
    assert result.exit_code == 0
    assert seen == [42]


def test_bench_run_seed_defaults_without_the_flag(monkeypatch):
    seen: list[int] = []
    monkeypatch.setattr(bench_cli, "set_global_seed", lambda s: seen.append(s) or s)
    CliRunner().invoke(bench, ["run"])
    assert seen == [DEFAULT_SEED]


def test_the_scorecard_records_the_seed(tmp_path):
    """A scorecard outlives its terminal; the seed has to travel with it."""
    out = tmp_path / "scorecard.md"
    result = CliRunner().invoke(bench, ["run", "--seed", "7", "--scorecard", str(out)])
    assert result.exit_code == 0
    assert "| seed | 7 |" in out.read_text()


def test_bench_run_writes_a_manifest(tmp_path):
    out = tmp_path / "run.json"
    result = CliRunner().invoke(bench, ["run", "--seed", "5", "--manifest", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["suite"] == "local"
    assert data["config"]["seed"] == 5
    assert data["config"]["extra"]["engine"] == "placeholder"
    assert data["manifest_hash"]


def test_a_filtered_run_does_not_fingerprint_as_the_whole_suite(tmp_path):
    """The suite hash describes what ran, or the regression gate would compare
    a one-task run against a three-task baseline and call it a pass."""
    full = tmp_path / "full.json"
    part = tmp_path / "part.json"
    CliRunner().invoke(bench, ["run", "--manifest", str(full)])
    CliRunner().invoke(bench, ["run", "--manifest", str(part), "--task", "local-sqli-login"])
    a = json.loads(full.read_text())
    b = json.loads(part.read_text())
    assert a["total"] > b["total"]
    assert a["suite_hash"] != b["suite_hash"]


def test_no_manifest_without_the_flag(tmp_path):
    result = CliRunner().invoke(bench, ["run"])
    assert result.exit_code == 0
    assert not list(tmp_path.iterdir())


def test_gate_passes_against_an_equal_baseline(tmp_path):
    base = tmp_path / "base.json"
    CliRunner().invoke(bench, ["run", "--manifest", str(base)])
    result = CliRunner().invoke(bench, ["run", "--baseline", str(base)])
    assert result.exit_code == 0
    assert "regression gate" in result.output


def test_gate_passes_when_there_is_no_baseline_yet(tmp_path):
    """A first run has nothing to regress against and must not fail."""
    result = CliRunner().invoke(bench, ["run", "--baseline", str(tmp_path / "absent.json")])
    assert result.exit_code == 0


def test_gate_fails_when_the_suite_changed_under_it(tmp_path):
    """A filtered run against a full-suite baseline is not a comparison."""
    base = tmp_path / "base.json"
    CliRunner().invoke(bench, ["run", "--manifest", str(base)])
    result = CliRunner().invoke(
        bench, ["run", "--baseline", str(base), "--task", "local-sqli-login"]
    )
    assert result.exit_code == 1
    assert "suite content changed" in result.output


def test_the_gate_runs_without_writing_a_manifest(tmp_path):
    """--baseline stands alone: CI checks, it does not have to publish."""
    base = tmp_path / "base.json"
    CliRunner().invoke(bench, ["run", "--manifest", str(base)])
    out = tmp_path / "unwritten.json"
    result = CliRunner().invoke(bench, ["run", "--baseline", str(base)])
    assert result.exit_code == 0
    assert not out.exists()


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


def test_cve_bench_suite_runs_through_its_own_runner(monkeypatch):
    import cyberai.cli.bench as mod
    from cyberai.bench.runner import BenchResult, BenchTask

    task = BenchTask(id="CVE-2024-2624", suite="cve-bench", target="http://127.0.0.1:9090")
    monkeypatch.setattr(mod.CVEBenchAdapter, "load_tasks", lambda self: [task])
    monkeypatch.setattr(
        mod,
        "make_cve_bench_runner",
        lambda adapter: (
            lambda t: BenchResult(
                task_id=t.id,
                suite=t.suite,
                solved=True,
                details={"grader_message": "Remote code execution successful"},
            )
        ),
    )

    result = CliRunner().invoke(bench, ["run", "--suite", "cve-bench", "--engine", "agent"])

    assert result.exit_code == 0
    assert "1/1" in result.output


def test_cve_bench_refuses_the_probe_engine(monkeypatch):
    import cyberai.cli.bench as mod

    monkeypatch.setattr(mod.CVEBenchAdapter, "load_tasks", lambda self: [])
    monkeypatch.setattr(
        mod, "make_cve_bench_runner", lambda adapter: pytest.fail("must not build a runner")
    )

    result = CliRunner().invoke(bench, ["run", "--suite", "cve-bench", "--engine", "real"])

    assert result.exit_code == 0
    assert "own grader" in result.output


def test_list_says_why_an_external_suite_is_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("CVEBENCH_DIR", str(tmp_path / "nowhere"))

    result = CliRunner().invoke(bench, ["list"])

    assert result.exit_code == 0
    assert "unavailable" in result.output
    # A missing optional dependency must not read as a suite of zero tasks.
    assert "local-sqli-login" in result.output


def test_task_filter_narrows_the_run_and_says_so():
    result = CliRunner().invoke(bench, ["run", "--task", "local-sqli-login"])

    assert result.exit_code == 0
    assert "filtered: 1 of 3" in result.output
    assert "0/1" in result.output, "the denominator is the selection"
    assert "local-cmdi-ping" not in result.output


def test_task_filter_accepts_several_ids():
    result = CliRunner().invoke(
        bench, ["run", "--task", "local-sqli-login", "--task", "local-cmdi-ping"]
    )

    assert result.exit_code == 0
    assert "filtered: 2 of 3" in result.output


def test_an_unfiltered_run_says_nothing_about_filtering():
    result = CliRunner().invoke(bench, ["run"])

    assert result.exit_code == 0
    assert "filtered" not in result.output


def test_a_typo_in_a_task_id_is_an_error_not_an_empty_run():
    result = CliRunner().invoke(bench, ["run", "--task", "local-sqli-logn"])

    assert result.exit_code != 0
    assert "unknown task id" in result.output
    # Scoring zero of zero tasks looks identical to a suite nobody can solve.
    assert "pass@1" not in result.output


def test_a_filtered_scorecard_carries_the_narrowed_denominator(tmp_path):
    out = tmp_path / "sc.md"
    result = CliRunner().invoke(
        bench, ["run", "--task", "local-sqli-login", "--scorecard", str(out)]
    )

    assert result.exit_code == 0
    text = out.read_text()
    assert "filtered" in text
    assert "1 of 3 tasks: local-sqli-login" in text


def test_the_grader_verdict_is_not_rendered_as_unknown(monkeypatch):
    """cve-bench keys its verdict differently; unknown must mean unknown."""
    import cyberai.cli.bench as mod
    from cyberai.bench.runner import BenchResult, BenchTask

    task = BenchTask(id="CVE-2024-2624", suite="cve-bench", target="http://127.0.0.1:9090")
    monkeypatch.setattr(mod.CVEBenchAdapter, "load_tasks", lambda self: [task])
    monkeypatch.setattr(
        mod,
        "make_cve_bench_runner",
        lambda adapter: (
            lambda t: BenchResult(
                task_id=t.id,
                suite=t.suite,
                solved=False,
                details={
                    "available": True,
                    "grader_status": False,
                    "agent_confirmed": 0,
                },
            )
        ),
    )

    result = CliRunner().invoke(bench, ["run", "--suite", "cve-bench", "--engine", "agent"])

    assert result.exit_code == 0
    # On cve-bench the grader sets the score, so the agent is the second view.
    assert "agent" in result.output
    assert "?" not in result.output, "a grader that answered is not an unknown"


def test_a_second_opinion_is_unknown_only_when_there_was_none():
    from cyberai.cli.bench import _second_opinion

    assert _second_opinion({"judge_solved": None}) is None
    assert _second_opinion({"judge_solved": False}) is False
    assert _second_opinion({"grader_status": True, "available": True, "agent_confirmed": 2}) is True
    assert _second_opinion({"grader_status": True, "available": True}) is False
    # A target that never came up has no second verdict to report.
    assert _second_opinion({"available": False}) is None
