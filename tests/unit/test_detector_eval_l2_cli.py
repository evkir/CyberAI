"""The L2 flags on `cyberai detector eval`, driven through the real command.

The live path needs a GPU and is out of reach here, but the replay path is
the same code from the flag down to the report, so everything except the
transport is exercised by these.
"""

import json
import pathlib

import pytest
from click.testing import CliRunner

from cyberai.cli.detector_eval import detector
from cyberai.core.security.eval_corpus import load_corpus
from cyberai.core.security.llm_classifier import _fingerprint, recording_header

CORPUS = str(pathlib.Path(__file__).resolve().parents[2] / "tests" / "corpus")


def _recording(tmp_path, verdict_for):
    verdicts = {_fingerprint(s.text): verdict_for(s) for s in load_corpus(CORPUS)}
    path = tmp_path / "verdicts.json"
    path.write_text(
        json.dumps({**recording_header("fast-coder:latest"), "verdicts": verdicts}),
        encoding="utf-8",
    )
    return path


@pytest.mark.unit
def test_replay_scores_the_corpus_without_a_model(tmp_path):
    """Every injection reaches the replay, whatever the corpus currently holds.

    The count used to be written here as a digit. Adding two samples turned a
    true assertion false without anything about the replay changing, which is
    a test measuring the corpus rather than the code under it. The corpus is
    the instrument, so it supplies the number.
    """
    injections = sum(1 for sample in load_corpus(CORPUS) if sample.is_injection)
    path = _recording(tmp_path, lambda s: "injection" if s.is_injection else "benign")
    result = CliRunner().invoke(detector, ["eval", "--corpus", CORPUS, "--l2-replay", str(path)])
    assert result.exit_code == 0, result.output
    assert f"TP {injections}" in result.output and "FP 0" in result.output


@pytest.mark.unit
def test_the_report_names_the_model_the_verdicts_came_from(tmp_path):
    """Not the mechanism that replayed them: a replayed run and the live run
    it came from describe one measurement and must render identically."""
    path = _recording(tmp_path, lambda s: "benign")
    report = tmp_path / "report.md"
    result = CliRunner().invoke(
        detector,
        ["eval", "--corpus", CORPUS, "--l2-replay", str(path), "--report", str(report)],
    )
    assert result.exit_code == 0, result.output
    assert "| layers | L1+L2 (fast-coder:latest) |" in report.read_text(encoding="utf-8")


@pytest.mark.unit
def test_a_stale_recording_stops_the_command(tmp_path):
    """Publishing a figure for a prompt nobody runs is worse than no figure."""
    path = _recording(tmp_path, lambda s: "benign")
    body = json.loads(path.read_text(encoding="utf-8"))
    body["prompt_sha256"] = "taken under an older prompt"
    path.write_text(json.dumps(body), encoding="utf-8")

    result = CliRunner().invoke(detector, ["eval", "--corpus", CORPUS, "--l2-replay", str(path)])
    assert result.exit_code != 0
    assert "different prompt" in result.output


@pytest.mark.unit
def test_json_output_says_which_layers_produced_it(tmp_path):
    path = _recording(tmp_path, lambda s: "benign")
    result = CliRunner().invoke(
        detector, ["eval", "--corpus", CORPUS, "--l2-replay", str(path), "--json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["layers"] == "L1+L2 (fast-coder:latest)"


@pytest.mark.unit
def test_without_the_flags_the_run_is_one_layer():
    """The default has to stay the pattern layer: no flag, no model, no wait."""
    result = CliRunner().invoke(detector, ["eval", "--corpus", CORPUS, "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["layers"] == "L1"
