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
