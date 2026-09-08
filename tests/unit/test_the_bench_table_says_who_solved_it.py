"""A published rate names the model's part in it, in the terminal.

Measured on 2026-09-08: `bench run --suite local --engine agent` printed
4/4 = 100.0% and nothing else. The run reached no model at all -- the
agent engine constructs its agents without a client -- and the fact was
recorded only in the scorecard, which a plain run never writes. A reader
of the terminal saw a perfect score on an AI platform and supplied the
missing premise themselves.

The roll-up already existed and already refused to average a split run.
It was called inside the scorecard branch, so it answered a question
nobody had asked yet.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from cyberai.bench.runner import BenchResult, SuiteReport
from cyberai.cli.bench import bench


def _report(*details: dict) -> SuiteReport:
    results = tuple(
        BenchResult(
            task_id=f"t{i}",
            suite="local",
            solved=True,
            duration_s=1.0,
            details=d,
        )
        for i, d in enumerate(details)
    )
    return SuiteReport(suite="local", total=len(results), solved=len(results), results=results)


def _run(report: SuiteReport):
    with patch("cyberai.cli.bench.run_suite", return_value=report):
        return CliRunner().invoke(bench, ["run", "--suite", "local"])


_MODEL_FREE = {"llm_calls": 0, "llm_zero_reason": "engine_uses_no_model"}


def test_a_model_free_run_says_so_next_to_the_score():
    result = _run(_report(_MODEL_FREE, _MODEL_FREE))
    assert result.exit_code == 0
    assert "pass@1" in result.output
    assert "llm calls: 0" in result.output
    assert "engine_uses_no_model" in result.output


def test_a_split_run_reports_the_split_rather_than_a_number():
    """Half a run reaching a model has no single answer worth publishing."""
    result = _run(_report(_MODEL_FREE, {"llm_calls": 3}))
    assert "llm calls:" in result.output
    assert "1 of 2" in result.output
    assert "llm calls: 0" not in result.output


def test_a_run_that_measured_nothing_prints_no_row():
    """Absent stays absent: a line reading `unknown` would be a value."""
    result = _run(_report({"note": "nothing recorded"}, {"note": "nothing recorded"}))
    assert "pass@1" in result.output
    assert "llm calls" not in result.output


def test_the_line_does_not_need_a_scorecard_to_appear():
    """The defect was the placement, not the computation.

    The roll-up ran only inside the `--scorecard` branch, so the terminal
    output of a plain run depended on whether a file had been requested.
    """
    result = _run(_report(_MODEL_FREE))
    assert "scorecard written" not in result.output
    assert "llm calls: 0" in result.output
