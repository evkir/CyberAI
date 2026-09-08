"""A zero from a dead target is not the same zero as a zero from the agent.

Measured 2026-09-08: docker_builder.start() logs an info line and returns
None when Docker is absent or the container fails, and the runners turn
that into an unsolved task carrying `available: False`. The terminal
printed the rate and nothing else, so a suite that never started reads
exactly like a suite the agent could not solve.

The scorecard has carried an availability column for this reason. A plain
run writes no scorecard, which left the caveat in a file the caller had to
ask for.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from cyberai.bench.runner import BenchResult, SuiteReport
from cyberai.cli.bench import bench


def _result(task_id: str, available, error=None) -> BenchResult:
    details = {} if available is None else {"available": available}
    return BenchResult(
        task_id=task_id,
        suite="local",
        solved=available is True,
        duration_s=1.0,
        error=error,
        details=details,
    )


def _run(*results: BenchResult):
    report = SuiteReport(
        suite="local",
        total=len(results),
        solved=sum(1 for r in results if r.solved),
        results=tuple(results),
    )
    with patch("cyberai.cli.bench.run_suite", return_value=report):
        return CliRunner().invoke(bench, ["run", "--suite", "local"])


_DOWN = "target not serving (docker unavailable or start failed)"


def test_a_dead_target_is_named_next_to_the_score():
    result = _run(
        _result("local-sqli-login", True),
        _result("local-ssrf-fetch", False, _DOWN),
    )
    assert result.exit_code == 0
    assert "1 of 2 targets never came up" in result.output
    assert "local-ssrf-fetch" in result.output


def test_the_reason_travels_with_the_name():
    """`docker is not installed` and `the app crashed` are different runs."""
    result = _run(_result("t1", False, _DOWN))
    # Short enough to survive the console wrapping the line; the full
    # sentence is split across two rows at this width and asserting on it
    # would test the terminal, not the message.
    assert "docker unavailable" in result.output


def test_a_run_where_everything_came_up_says_nothing():
    result = _run(_result("t1", True), _result("t2", True))
    assert "never came up" not in result.output
    assert "pass@1" in result.output


def test_an_engine_that_measures_no_availability_says_nothing():
    """The placeholder engine records none, and absence is not a False."""
    result = _run(_result("t1", None), _result("t2", None))
    assert "never came up" not in result.output


def test_the_note_follows_the_score_it_qualifies():
    """The rate comes first and the caveat sits under it.

    Printed above the score the note reads as a run that failed to start;
    printed below it, as the reason the number is what it is. The first
    version of this test asserted only that both lines existed, which a
    reordering leaves true.
    """
    result = _run(_result("t1", False, _DOWN), _result("t2", False, _DOWN))
    assert "2 of 2 targets never came up" in result.output
    assert "pass@1: 0/2" in result.output
    assert result.output.index("pass@1") < result.output.index("never came up")
