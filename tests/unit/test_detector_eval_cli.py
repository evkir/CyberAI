"""The evaluator is only a measurement surface if the command exists.

Mutation testing found this gap: unregistering the group from __main__ left
every unit test green while `cyberai detector eval` stopped existing. A
module with a working API and no route to it is the same defect as a helper
with no call site, just from the other end.

These run the real Click app, not a stub. The point is the wiring: the
command resolves, the required option is required, a bad corpus fails loudly
instead of printing an empty table, and the JSON payload keeps the shape a
document quotes from.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cyberai.__main__ import cli

pytestmark = pytest.mark.unit

CORPUS = str(Path(__file__).resolve().parents[1] / "corpus")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_the_detector_group_is_reachable_from_the_root_command(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["detector", "--help"])
    assert result.exit_code == 0, result.output
    assert "eval" in result.output


def test_eval_renders_the_per_subclass_table(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["detector", "eval", "--corpus", CORPUS])
    assert result.exit_code == 0, result.output
    assert "overall" in result.output
    assert "blind:" in result.output


def test_the_corpus_option_is_required(runner: CliRunner) -> None:
    """No hidden default. A published command names the corpus it measured."""
    result = runner.invoke(cli, ["detector", "eval"])
    assert result.exit_code != 0
    assert "--corpus" in result.output


def test_a_directory_without_a_manifest_fails_loudly(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["detector", "eval", "--corpus", str(tmp_path)])
    assert result.exit_code != 0
    assert "manifest" in result.output


def test_json_output_carries_the_shape_documents_quote(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["detector", "eval", "--corpus", CORPUS, "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["threshold"] == 50
    assert payload["corpus"] == CORPUS
    assert payload["overall"]["false_positive_rate"] is not None
    assert payload["blind_subclasses"]
    assert len(payload["scores"]) == payload["overall"]["total"]


def test_the_threshold_option_changes_the_measurement(runner: CliRunner) -> None:
    """Two thresholds, two answers, from the same corpus in one process."""
    strict = json.loads(
        runner.invoke(cli, ["detector", "eval", "--corpus", CORPUS, "--json"]).output
    )
    loose = json.loads(
        runner.invoke(
            cli, ["detector", "eval", "--corpus", CORPUS, "--threshold", "25", "--json"]
        ).output
    )
    assert loose["threshold"] == 25
    assert loose["overall"]["true_positive"] > strict["overall"]["true_positive"]
    assert len(loose["blind_subclasses"]) < len(strict["blind_subclasses"])


def test_report_writes_the_markdown_artifact(runner: CliRunner, tmp_path: Path) -> None:
    """The flag that produces the committed file, exercised directly.

    The architecture gate compares the committed artifact against a fresh
    render, which proves the content but not the route: it calls
    render_report itself and would stay green if --report were removed. This
    drives the option.
    """
    out = tmp_path / "nested" / "baseline.md"
    result = runner.invoke(cli, ["detector", "eval", "--corpus", CORPUS, "--report", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    body = out.read_text(encoding="utf-8")
    assert body.startswith("# Detector Evaluation")
    assert "| threshold | 50 |" in body
    assert "## Blind subclasses" in body


def test_report_creates_missing_parent_directories(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "a" / "b" / "c.md"
    assert (
        runner.invoke(cli, ["detector", "eval", "--corpus", CORPUS, "--report", str(out)]).exit_code
        == 0
    )
    assert out.is_file()


def test_report_records_the_threshold_it_was_run_at(runner: CliRunner, tmp_path: Path) -> None:
    """A report that does not name its threshold describes nothing."""
    out = tmp_path / "loose.md"
    runner.invoke(
        cli,
        ["detector", "eval", "--corpus", CORPUS, "--threshold", "25", "--report", str(out)],
    )
    assert "| threshold | 25 |" in out.read_text(encoding="utf-8")


def test_the_table_still_prints_when_a_report_is_written(runner: CliRunner, tmp_path: Path) -> None:
    """Writing a file is not a reason to make the run invisible in the terminal."""
    out = tmp_path / "r.md"
    result = runner.invoke(cli, ["detector", "eval", "--corpus", CORPUS, "--report", str(out)])
    assert "report written" in result.output
    assert "overall" in result.output
