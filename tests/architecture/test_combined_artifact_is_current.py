"""The published two-layer figure must be reproducible without a GPU.

The pattern layer can be re-run anywhere, so its artifact is pinned against a
fresh evaluation. The second layer cannot: CI has no ollama, and a live pass
over the corpus costs minutes. An artifact nothing checks is exactly the shape
this sprint exists to remove, so the verdicts the live run obtained are
committed beside the report and replayed here.

What that pins and what it does not, stated rather than left to be discovered:
the composition, the category weight, the threshold and the pattern layer are
all re-derived, so moving any of them fails this file. The model's judgement
is not re-derived -- it is the recording. Moving the prompt is caught anyway,
because a recording carries the prompt's fingerprint and refuses to load
under a different one.
"""

import json
import pathlib

from cyberai.core.security.eval_corpus import (
    evaluate,
    label_counts,
    load_corpus,
    render_report,
)
from cyberai.core.security.guard import DEFAULT_THRESHOLD
from cyberai.core.security.llm_classifier import (
    LLMClassifier,
    _fingerprint,
    combined_scorer,
    recorded_transport,
    recording_model,
)

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "corpus"
_ARTIFACT = _ROOT / "examples" / "detector-eval" / "combined.md"
_RECORDING = _ROOT / "examples" / "detector-eval" / "l2-verdicts.json"

_REGENERATE = (
    "cyberai detector eval --corpus tests/corpus --l2 "
    "--l2-record examples/detector-eval/l2-verdicts.json "
    "--report examples/detector-eval/combined.md"
)


def _fresh() -> str:
    samples = load_corpus(_CORPUS)
    classifier = LLMClassifier(transport=recorded_transport(_RECORDING))
    result = evaluate(samples, threshold=DEFAULT_THRESHOLD, scorer=combined_scorer(classifier))
    return render_report(
        result,
        "tests/corpus",
        label_counts(samples),
        layers=f"L1+L2 ({recording_model(_RECORDING)})",
    )


def _without_timestamp(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.startswith("| timestamp |")]


def test_the_artifact_and_its_recording_exist() -> None:
    assert _ARTIFACT.is_file(), f"missing; produce it with: {_REGENERATE}"
    assert _RECORDING.is_file(), f"missing; produce it with: {_REGENERATE}"


def test_the_committed_report_matches_a_replayed_run() -> None:
    committed = _without_timestamp(_ARTIFACT.read_text(encoding="utf-8"))
    assert committed == _without_timestamp(_fresh()), (
        f"the two-layer report is stale or was edited by hand; re-run: {_REGENERATE}"
    )


def test_the_recording_covers_every_sample() -> None:
    """A partial recording would silently measure a mix of two configurations.

    Samples the recording does not hold fall back to the pattern layer alone,
    which is the right behaviour at runtime and the wrong basis for a
    published figure: the document would claim two layers and describe one.
    """
    classifier = LLMClassifier(transport=recorded_transport(_RECORDING))
    missing = [s.id for s in load_corpus(_CORPUS) if classifier.classify(s.text) is None]
    assert not missing, f"no recorded verdict for {missing}; re-run: {_REGENERATE}"


def test_the_recording_holds_no_verdict_for_a_sample_that_is_gone() -> None:
    """The other direction, and merging is why it now needs saying.

    While the writer replaced the file, a key could only exist because a
    sample had just produced it. The writer merges, so a sample that is
    renamed away or deleted leaves its answer behind, and the recording would
    accumulate verdicts for text nothing in the corpus holds. Harmless to a
    replay, which looks keys up rather than iterating them, and exactly the
    shape this repository keeps finding: a producer whose output no longer
    has a consumer.
    """
    recorded = set(json.loads(_RECORDING.read_text(encoding="utf-8"))["verdicts"])
    live = {_fingerprint(sample.text) for sample in load_corpus(_CORPUS)}
    orphans = sorted(recorded - live)
    assert not orphans, f"{len(orphans)} verdicts belong to no sample; re-run: {_REGENERATE}"


def test_the_two_layer_report_beats_the_one_layer_report() -> None:
    """The reason the layer exists, pinned as a number rather than a claim.

    Not a fixed target: the pattern layer is re-derived here, so this compares
    what the two configurations do today. It fails if a change ever makes the
    second layer cost recall instead of adding it.
    """
    samples = load_corpus(_CORPUS)
    classifier = LLMClassifier(transport=recorded_transport(_RECORDING))
    one = evaluate(samples, threshold=DEFAULT_THRESHOLD)
    two = evaluate(samples, threshold=DEFAULT_THRESHOLD, scorer=combined_scorer(classifier))
    assert two.overall.recall > one.overall.recall
    assert two.overall.false_positive <= one.overall.false_positive
    assert two.blind_subclasses() == []
