"""Numbers in the security document must be the numbers in the artifact.

docs/security/adversarial-robustness.md now quotes recall, precision and a
false-positive rate. Prose that carries a measurement is the exact surface
this repository has already published stale figures on twice: a README run
table that lagged the scorecard by two days, and a threshold justified by a
corpus that no longer existed.

The rule this enforces is narrow on purpose. Every percentage the document
states about the detector must appear in the committed report, which is
itself pinned against a fresh run by test_baseline_artifact_is_current. So a
figure reaches the document only by travelling through a command, and the
chain from the code to the sentence a reader believes has no hand-written
link in it.

Numbers the artifact does not carry are checked against a re-run instead:
the document quotes the detector's own cut of 25 as well, and the committed
report is taken at the production threshold. Rather than commit a second
artifact for a threshold nobody ships, that pair is recomputed here.

The production threshold is imported, never written as a literal. An earlier
revision of this file hard-coded 50, and mutation testing found it: moving
DEFAULT_THRESHOLD left every test here green while the document they guard
went on describing a configuration nobody ships. A test that copies the
constant it is checking has stopped checking anything.

What is not pinned is the wording. A test that pinned sentences would fail
on every edit to a paragraph and teach the reviewer to regenerate prose
without reading it.
"""

import pathlib
import re

import pytest

from cyberai.core.security.eval_corpus import evaluate, load_corpus
from cyberai.core.security.guard import DEFAULT_THRESHOLD

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DOC = _ROOT / "docs" / "security" / "adversarial-robustness.md"
# The research document carries the same figures for a different reader.
# A rule scoped to one file lets a second file drift, which is the failure
# this module exists to stop -- one heading, then one file, same shape.
_RESEARCH = _ROOT / "docs" / "research" / "detector-v2.md"
_MEASURED_DOCS = (_DOC, _RESEARCH)
_ARTIFACT = _ROOT / "examples" / "detector-eval" / "baseline.md"
_COMBINED = _ROOT / "examples" / "detector-eval" / "combined.md"
_CORPUS = _ROOT / "tests" / "corpus"

_ALT_THRESHOLD = 25


def _percentages(text: str) -> set[str]:
    return set(re.findall(r"\d+\.\d%", text))


def _section(text: str, heading: str) -> str:
    """The body under one heading, up to the next one at any level."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("#")),
        len(lines),
    )
    return "\n".join(lines[start:end])


@pytest.mark.architecture
def test_the_document_quotes_the_command_that_reproduces_it() -> None:
    body = _DOC.read_text(encoding="utf-8")
    assert "cyberai detector eval --corpus tests/corpus" in body


@pytest.mark.architecture
def test_the_document_quotes_the_command_that_replays_the_second_layer() -> None:
    """A figure nobody can reproduce is a claim, whatever produced it."""
    body = _DOC.read_text(encoding="utf-8")
    assert "--l2-replay" in body
    assert "examples/detector-eval/l2-verdicts.json" in body


@pytest.mark.architecture
def test_production_threshold_figures_come_from_the_artifact() -> None:
    """Every figure in the document, not only those under one heading.

    The rule was scoped to `## Measured coverage` when that was the only
    section carrying numbers. A second layer brought a second section and a
    second artifact, and a rule that reads one heading would have let the
    new figures through unchecked -- which is the failure it exists to stop.
    """
    fresh_alt = _percentages(_rendered_at(_ALT_THRESHOLD))
    from_artifact = _percentages(_ARTIFACT.read_text(encoding="utf-8"))
    from_artifact |= _percentages(_COMBINED.read_text(encoding="utf-8"))

    for path in _MEASURED_DOCS:
        quoted = _percentages(path.read_text(encoding="utf-8"))
        assert quoted, f"no figures in {path.name} -- regex broke or file emptied"
        unaccounted = quoted - from_artifact - fresh_alt
        assert not unaccounted, (
            f"figures in {path.name} that no run produced: {sorted(unaccounted)}. "
            "Re-run: cyberai detector eval --corpus tests/corpus "
            "--report examples/detector-eval/baseline.md"
        )


def _rendered_at(threshold: int) -> str:
    """Percentages the detector produces at a threshold with no committed report."""
    result = evaluate(load_corpus(_CORPUS), threshold=threshold)
    overall = result.overall
    parts = []
    for value in (overall.recall, overall.precision, overall.false_positive_rate):
        if value is not None:
            parts.append(f"{value * 100:.1f}%")
    return " ".join(parts)


@pytest.mark.architecture
def test_the_blind_subclasses_named_in_prose_are_the_measured_ones() -> None:
    """The list is prose and drifts the way a number does."""
    doc = _section(_DOC.read_text(encoding="utf-8"), "## Measured coverage")
    measured = evaluate(load_corpus(_CORPUS), threshold=DEFAULT_THRESHOLD).blind_subclasses()
    assert len(measured) > 0, "nothing is blind any more; rewrite the section"

    words = {4: "Four", 5: "Five", 6: "Six", 7: "Seven", 8: "Eight"}
    word = words.get(len(measured))
    assert word, f"add {len(measured)} to the word map"
    assert re.search(rf"{word} injection subclasses", doc), (
        f"{len(measured)} subclasses are blind now: {measured}. "
        "The document states a different count."
    )


@pytest.mark.architecture
def test_the_readme_links_to_the_artifact() -> None:
    body = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "examples/detector-eval/baseline.md" in body


@pytest.mark.architecture
def test_the_readme_links_to_the_research_document() -> None:
    body = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/research/detector-v2.md" in body
