"""The eval corpus must stay measurable, not just present.

A corpus is an instrument. An instrument that drifts silently publishes
numbers that mean nothing, and the numbers from this one are meant to be
published: precision and recall before and after the detector is rebuilt,
on the same samples.

Four ways it can rot, all of them quiet:

Manifest and directory disagree. A sample added without a manifest line is
scored by nothing; a manifest line without a file is a phantom that changes
the denominator. Both are checked in both directions.

A sample loses its provenance. `source` separates a bypass written by hand
from real output captured off a real target. Published numbers have to be
able to say how much of the corpus was which, so a captured sample without
a date and an origin is rejected here rather than discovered later.

The classes shrink. Forty per class is the floor from the sprint's
acceptance criteria. Below that a percentage point stops being a
measurement.

The floor gets satisfied with copies. Duplicate content inflates both class
sizes and whichever metric the duplicates happen to favour, so samples are
compared by content, not by filename.

What is deliberately not asserted: that any sample scores any particular
way. That is the measurement, and it is what changes when the detector is
rebuilt. A test that pinned it would have to be rewritten to stay green,
which is the definition of an instrument that measures its own calibration.
"""

import hashlib
import json
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "corpus"
_MANIFEST = _CORPUS / "manifest.jsonl"

MIN_PER_CLASS = 40
LABELS = {"injection": "injections", "benign": "benign"}
SOURCES = {"captured", "synthetic", "public"}
REQUIRED = ("id", "path", "label", "subclass", "source")
# How a successful attack would be observed, per injection. disclose: a canary
# planted in the system prompt comes back in the answer. act: the model calls a
# tool or reaches an outbound collector. unobservable: success is a change of
# behaviour with no automatic predicate.
OUTCOMES = {"disclose", "act", "unobservable"}
# Below this the attack-success denominator stops being a measurement, for the
# same reason MIN_PER_CLASS exists. Without it every sample could be relabelled
# unobservable and the instrument would report nothing, greenly.
MIN_OBSERVABLE = 20


def _entries() -> list[dict]:
    lines = _MANIFEST.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _sample_files() -> set[str]:
    found = set()
    for label_dir in LABELS.values():
        for path in (_CORPUS / label_dir).glob("*.txt"):
            found.add(f"{label_dir}/{path.name}")
    return found


@pytest.mark.architecture
def test_every_manifest_entry_has_its_file() -> None:
    missing = [e["path"] for e in _entries() if not (_CORPUS / e["path"]).is_file()]
    assert not missing, missing


@pytest.mark.architecture
def test_every_file_has_its_manifest_entry() -> None:
    declared = {e["path"] for e in _entries()}
    orphans = sorted(_sample_files() - declared)
    assert not orphans, orphans


@pytest.mark.architecture
def test_entries_are_complete_and_well_formed() -> None:
    seen_ids = set()
    for e in _entries():
        for field in REQUIRED:
            assert e.get(field), (e.get("id"), field)
        assert e["label"] in LABELS, e
        assert e["source"] in SOURCES, e
        assert e["path"].startswith(LABELS[e["label"]] + "/"), e
        assert e["id"] not in seen_ids, e["id"]
        seen_ids.add(e["id"])
        if e["source"] == "captured":
            assert e.get("captured_at"), e["id"]
            assert e.get("origin"), e["id"]


@pytest.mark.architecture
def test_both_classes_meet_the_floor() -> None:
    counts = {"injection": 0, "benign": 0}
    for e in _entries():
        counts[e["label"]] += 1
    for label, n in counts.items():
        assert n >= MIN_PER_CLASS, (label, n, MIN_PER_CLASS)


@pytest.mark.architecture
def test_no_sample_is_a_copy_of_another() -> None:
    by_digest: dict[str, list[str]] = {}
    for rel in sorted(_sample_files()):
        digest = hashlib.sha256((_CORPUS / rel).read_bytes()).hexdigest()
        by_digest.setdefault(digest, []).append(rel)
    dupes = [group for group in by_digest.values() if len(group) > 1]
    assert not dupes, dupes


@pytest.mark.architecture
def test_no_sample_is_empty() -> None:
    empty = [rel for rel in sorted(_sample_files()) if not (_CORPUS / rel).read_bytes().strip()]
    assert not empty, empty


@pytest.mark.architecture
def test_every_injection_declares_how_success_would_be_observed() -> None:
    """Attack success rate needs a predicate per sample, and text cannot supply it.

    Deriving the predicate from the sample body was tried and failed: three
    base64 samples, two homoglyph samples and one zero-width sample decode to
    a request for the system prompt, and a classifier reading the raw text
    puts them elsewhere. Hiding its own text is what those samples are for.
    So the predicate is authored data, declared here, and benign samples
    carry none because they have no success to observe.
    """
    wrong = [
        (e["id"], e.get("outcome"))
        for e in _entries()
        if (e["label"] == "injection") != (e.get("outcome") in OUTCOMES)
    ]
    assert not wrong, wrong


@pytest.mark.architecture
def test_the_observable_group_is_large_enough_to_divide_by() -> None:
    counts = {name: 0 for name in OUTCOMES}
    unknown = []
    for e in _entries():
        if e["label"] != "injection":
            continue
        outcome = e.get("outcome")
        if outcome in counts:
            counts[outcome] += 1
        else:
            unknown.append((e["id"], outcome))
    # A missing or misspelled value is the other test's finding; counting it
    # here as a KeyError would replace that message with a traceback.
    assert not unknown, unknown
    assert counts["disclose"] >= MIN_OBSERVABLE, counts
    assert all(n > 0 for n in counts.values()), counts
