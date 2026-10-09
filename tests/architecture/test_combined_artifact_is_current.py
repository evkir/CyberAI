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

    This asserted an empty blind list until 2026-10-08, and that assertion was
    true for as long as no sample defeated both layers. Four did: the stative
    subclass states an attacker's goal as a fact about the world rather than
    asking for it, and neither patterns nor model score it above zero. The
    assertion is now that the second layer shrinks the blind list and that
    what survives is named -- a list that merely got shorter would let the
    next technique in without a word.

    It also asserted that the second layer costs no precision, and that held
    only while the benign class was captured tool output. Sixty server
    descriptions from the public MCP registry were added on 2026-10-09 and
    the model flagged four of them, three of which name an assistant or a
    client: a server card addresses the assistant by construction, and the
    classifier reads being addressed as being steered. Patterns flag none of
    the sixty. So the cost is real, it is bounded here rather than denied,
    and the bound is what a change has to answer to.
    """
    samples = load_corpus(_CORPUS)
    classifier = LLMClassifier(transport=recorded_transport(_RECORDING))
    one = evaluate(samples, threshold=DEFAULT_THRESHOLD)
    two = evaluate(samples, threshold=DEFAULT_THRESHOLD, scorer=combined_scorer(classifier))
    one_recall, two_recall = one.overall.recall, two.overall.recall
    assert one_recall is not None and two_recall is not None, "a corpus with no injections"
    assert two_recall > one_recall
    # The second layer buys recall with precision, and where it pays is the
    # part worth pinning. Measured 2026-10-09: patterns flag no benign
    # sample at all, and every false positive the model adds sits in the
    # class of prose that addresses an assistant -- a server card is written
    # for one, and being addressed reads as being steered. A literal count
    # would measure the corpus; what must stay true is that the captured
    # half remains clean and that the cost is confined to one named class.
    assert one.overall.false_positive == 0, one.overall.false_positive
    paid = sorted(name for name, c in two.by_subclass.items() if c.false_positive > 0)
    assert paid == ["server_card"], paid
    captured = {s.subclass for s in samples if s.label == "benign"} - {"server_card"}
    assert captured, "the captured benign half is gone"
    assert all(two.by_subclass[name].false_positive == 0 for name in captured)
    blind_one, blind_two = one.blind_subclasses(), two.blind_subclasses()
    assert set(blind_two) < set(blind_one), (blind_one, blind_two)
    assert blind_two == ["stative"], blind_two
