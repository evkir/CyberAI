"""The committed detector report must be what the detector produces now.

Same shape as the scorecard gate, for the same reason. A published figure
that lags the code by two days is the defect this repository has already had
once: the card showed 28 requests where a re-run produced 21, and nothing
failed. The rule -- these numbers come from a measured run, never by hand --
gates nothing while it is only prose.

So the artifact is regenerated in memory and compared cell by cell against
the committed file. The timestamp is excluded: it changes on every run by
construction and says nothing about the measurement. Everything else must
match, which means editing the report by hand fails here, and so does
changing the detector without re-running the command that writes it.

The failure message names the command rather than the diff, because the fix
is never to edit this file.
"""

import pathlib

import pytest

from cyberai.core.security.eval_corpus import (
    evaluate,
    label_counts,
    load_corpus,
    render_report,
)
from cyberai.core.security.guard import DEFAULT_THRESHOLD

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "corpus"
_ARTIFACT = _ROOT / "examples" / "detector-eval" / "baseline.md"

_REGENERATE = (
    "cyberai detector eval --corpus tests/corpus --report examples/detector-eval/baseline.md"
)


def _rows(text: str) -> list[list[str]]:
    """Every pipe-table row in the document, timestamp row dropped."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip()[1:-1].split("|")]
        if cells and cells[0] == "timestamp":
            continue
        rows.append(cells)
    return rows


def _fresh() -> str:
    samples = load_corpus(_CORPUS)
    result = evaluate(samples, threshold=DEFAULT_THRESHOLD)
    return render_report(result, "tests/corpus", label_counts(samples))


@pytest.mark.architecture
def test_the_artifact_exists() -> None:
    assert _ARTIFACT.is_file(), f"missing; produce it with: {_REGENERATE}"


@pytest.mark.architecture
def test_every_committed_cell_matches_a_fresh_run() -> None:
    committed = _rows(_ARTIFACT.read_text(encoding="utf-8"))
    fresh = _rows(_fresh())
    assert committed == fresh, f"the report is stale or was edited by hand; re-run: {_REGENERATE}"


@pytest.mark.architecture
def test_the_prose_around_the_tables_matches_too() -> None:
    """Not only the numbers: the blind list is prose and drifts the same way."""
    committed = _ARTIFACT.read_text(encoding="utf-8").splitlines()
    fresh = _fresh().splitlines()
    skip = "| timestamp |"
    committed = [line for line in committed if not line.startswith(skip)]
    fresh = [line for line in fresh if not line.startswith(skip)]
    assert committed == fresh, f"re-run: {_REGENERATE}"


@pytest.mark.architecture
def test_the_artifact_is_measured_at_the_production_threshold() -> None:
    """A report taken at some other threshold would describe a product nobody ships."""
    body = _ARTIFACT.read_text(encoding="utf-8")
    assert f"| threshold | {DEFAULT_THRESHOLD} |" in body, DEFAULT_THRESHOLD
