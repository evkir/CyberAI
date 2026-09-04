"""A technique's informal name in prose is tied to the subclass that measures it.

The security document said base64 encoding scored zero on every sample in
the corpus. It had been false since the day blobs began to be decoded and
rescanned, and nothing failed: the artifact calls that group of samples
`encoded`, the sentence called it `base64`, and no test connected the two
names. The percentage gate could not help either -- the sentence carried no
percentage at all, which is what let an unfalsifiable claim sit in a
security document for days.

So the informal names are declared here and checked in both directions. A
name has to denote a subclass the corpus actually holds, and a subclass name
kept here has to be used by at least one of the documents; an alias nobody
writes is a mapping without a reader.

The claim that is checked is the one that went wrong: a sentence saying a
technique scores zero. That is the strongest thing a limits section can say
about a bypass and the easiest to leave behind, because it stops being true
the moment the detector improves. Prose that states a figure instead is
already covered, since every percentage in these documents is pinned against
a run.
"""

import pathlib
import re

from cyberai.core.security.eval_corpus import evaluate, load_corpus
from cyberai.core.security.guard import DEFAULT_THRESHOLD

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CORPUS = _ROOT / "tests" / "corpus"
_DOCS = (
    _ROOT / "docs" / "security" / "adversarial-robustness.md",
    _ROOT / "docs" / "research" / "detector-v2.md",
)

# What the prose calls a technique, and the manifest subclass that measures it.
_ALIAS_TO_SUBCLASS = {
    "base64": "encoded",
    "homoglyph": "homoglyph",
    "paraphrase": "paraphrase",
    "social": "social",
}

# "zero" as a measurement. Not "zero-width", which is a class of character.
_ZERO = re.compile(r"\bzero\b(?!-)", re.IGNORECASE)


def _recalls() -> dict[str, float | None]:
    result = evaluate(load_corpus(_CORPUS), threshold=DEFAULT_THRESHOLD)
    return {name: metrics.recall for name, metrics in result.by_subclass.items()}


def _sentences(text: str) -> list[str]:
    return re.split(r"(?<=[.:])\s+", " ".join(text.split()))


def test_every_alias_names_a_subclass_the_corpus_holds() -> None:
    recalls = _recalls()
    unknown = sorted(
        alias for alias, subclass in _ALIAS_TO_SUBCLASS.items() if subclass not in recalls
    )
    assert not unknown, f"alias pointing at no subclass: {unknown}"


def test_every_alias_is_used_by_a_document() -> None:
    """An alias no document writes is a mapping with no reader."""
    bodies = [path.read_text(encoding="utf-8") for path in _DOCS]
    unused = sorted(
        alias
        for alias in _ALIAS_TO_SUBCLASS
        if not any(re.search(rf"\b{alias}\b", body, re.IGNORECASE) for body in bodies)
    )
    assert not unused, f"alias no document uses: {unused}; drop it or write about it"


def test_no_technique_is_called_blind_unless_it_measures_zero() -> None:
    recalls = _recalls()
    wrong = []
    for path in _DOCS:
        for sentence in _sentences(path.read_text(encoding="utf-8")):
            if not _ZERO.search(sentence):
                continue
            for alias, subclass in _ALIAS_TO_SUBCLASS.items():
                if subclass not in recalls:
                    continue
                if re.search(rf"\b{alias}\b", sentence, re.IGNORECASE) and recalls[subclass]:
                    wrong.append((path.name, alias, recalls[subclass], sentence[:80]))
    assert not wrong, f"prose says a technique scores zero and the corpus disagrees: {wrong}"
