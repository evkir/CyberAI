"""The prose about the second layer's cost is re-derived, not remembered.

Two docstrings carry numbers that follow the corpus: how many samples the
pattern layer settles on its own, how large the corpus is, and how many
questions therefore reach the model. All three were wrong before this file
existed -- the guard said 28 of 94 against a measured 32 of 96, and the
classifier said 94 where the answer was 64, because it named the corpus
where the quantity is the corpus minus what the short circuit removed.

Numbers that depend on data are not written as digits without something
re-deriving them (rule 57). This is that something. It asserts in both
directions: the prose must match the measurement, and the measurement must
be reachable from the corpus the command actually reads.

What these assertions do not hold, established by mutation rather than left
to be discovered. Moving a numerator in either docstring is caught by that
docstring's own test alone -- the third assertion compares denominators, so
it agrees whenever both sentences name the same corpus size and says nothing
about the counts inside them. A reader looking for one gate over the whole
arithmetic will not find it here. Separately, the uniqueness check inside
_claim is not itself pinned: a second sentence matching the same pattern
would make the read ambiguous, and removing that check keeps every test
green.
"""

import pathlib
import re

from cyberai.core.security.eval_corpus import load_corpus
from cyberai.core.security.guard import DEFAULT_THRESHOLD
from cyberai.core.security.injection_detector import l1_scorer

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "corpus"
_GUARD = _ROOT / "cyberai" / "core" / "security" / "guard.py"
_CLASSIFIER = _ROOT / "cyberai" / "core" / "security" / "llm_classifier.py"


def _measured() -> tuple[int, int, int]:
    """(skipped, total, asked) for the corpus the published command reads."""
    samples = load_corpus(_CORPUS)
    skipped = sum(1 for s in samples if l1_scorer(s.text) >= DEFAULT_THRESHOLD)
    return skipped, len(samples), len(samples) - skipped


def _claim(path: pathlib.Path, pattern: str) -> tuple[int, ...]:
    """The numbers in one named sentence, not the first digits in the file."""
    text = re.sub(r"\s+(#|\*)?\s*", " ", path.read_text(encoding="utf-8"))
    found = re.findall(pattern, text)
    assert len(found) == 1, f"{path.name}: {len(found)} sentences match {pattern!r}"
    return tuple(int(n) for n in found[0])


def test_the_guard_names_the_measured_short_circuit() -> None:
    skipped, total, _ = _measured()
    claimed = _claim(_GUARD, r"short circuit skips (\d+) of (\d+) samples")
    assert claimed == (skipped, total)


def test_the_classifier_names_the_questions_that_reach_the_model() -> None:
    _, total, asked = _measured()
    claimed = _claim(_CLASSIFIER, r"settled -- (\d+) of the (\d+) samples")
    assert claimed == (asked, total)


def test_both_sentences_name_one_corpus_size() -> None:
    """A corpus size agreed on by accident is not agreement.

    This is a denominator check. It does not look at the counts the two
    sentences report, which their own tests hold.
    """
    skipped, total, asked = _measured()
    assert skipped + asked == total
    assert _claim(_GUARD, r"short circuit skips (\d+) of (\d+) samples")[1] == total
    assert _claim(_CLASSIFIER, r"settled -- (\d+) of the (\d+) samples")[1] == total
