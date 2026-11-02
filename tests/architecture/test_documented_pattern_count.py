"""Documents that name the detector's size must name the real one.

README said 33 patterns; docs/security/adversarial-robustness.md and the
module docstring of cyberai/core/safety.py said thirty-eight. The detector
holds 33. Two documents were wrong, in prose, in a security section, and
nothing failed -- the same shape as the version badge and the stale
scorecard, on a number a reviewer can check in one line.

The count is written three ways across the repository: a digit in README and
an English word in two docstring-style texts. All three are pinned here
against len(INJECTION_PATTERNS), so a pattern added or removed fails until
the prose catches up. That is the point: the failure is the reminder.

Only the count is pinned, not the sentences around it. A test that pinned
the wording would fail on every edit to a paragraph and teach the reviewer
to regenerate it without reading, which is how a document ends up asserting
something nobody checked.

The half that rejects a stale word read whitespace-separated tokens until
2026-11-02. Both prose texts end the count with punctuation, so the spelled
count was never a token and no stale word could ever be found: the check
was green on every input, including one carrying both the old count and the
new. Words are taken with a pattern now, and the mutation that proves it is
a page naming two counts at once.
"""

import pathlib
import re

from cyberai.core.security.injection_detector import (
    COMPILED_PATTERNS,
    INJECTION_PATTERNS,
)

_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Splitting on whitespace leaves the punctuation attached: both texts write the
# count as `thirty-three;` and `thirty-three.`, so no spelled count was ever a
# token and the stale half of the check below passed on every input it saw.
_WORDS_IN = re.compile(r"[a-z]+(?:-[a-z]+)*").findall

_WORDS = {
    31: "thirty-one",
    33: "thirty-three",
    38: "thirty-eight",
    34: "thirty-four",
}


def _text(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


def test_compiled_patterns_cover_every_declared_pattern() -> None:
    assert len(COMPILED_PATTERNS) == len(INJECTION_PATTERNS)


def test_digit_documents_name_the_real_pattern_count() -> None:
    n = len(INJECTION_PATTERNS)
    for rel in ("README.md", "docs/research/detector-v2.md"):
        assert f"{n} patterns" in _text(rel), (rel, n)


def test_prose_documents_name_the_real_pattern_count() -> None:
    n = len(INJECTION_PATTERNS)
    word = _WORDS.get(n)
    assert word is not None, f"add {n} to _WORDS"
    for rel in ("docs/security/adversarial-robustness.md", "cyberai/core/safety.py"):
        body = _text(rel)
        assert word in body, (rel, word)
        stale = {w for k, w in _WORDS.items() if k != n}
        assert not (stale & set(_WORDS_IN(body))), (rel, stale)
