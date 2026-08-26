"""The threshold's justification must match the detector's arithmetic.

DEFAULT_THRESHOLD is 50 and risk_score is len(matches) * 25, and the guard's
docstring read that pair as "two independent categories must agree". It is
false. Matches are counted per pattern, not per category, and seven of the
nine categories hold more than one pattern, so a single category reaches the
threshold alone.

The claim sat in the paragraph that justifies a production default: prose a
reviewer checks in one line, asserted by nothing. Same shape as the version
badge and the stale scorecard.

What is pinned here is the arithmetic, not the wording. The docstring check
fires only while one category can still reach the threshold on its own; when
W3 rescores per unique category the property becomes true and the check steps
aside by itself, instead of having to be remembered and deleted.
"""

import pathlib
from collections import Counter

import pytest

from cyberai.core.security.guard import DEFAULT_THRESHOLD
from cyberai.core.security.injection_detector import INJECTION_PATTERNS, detect_injection

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_GUARD = _ROOT / "cyberai" / "core" / "security" / "guard.py"

# Two patterns, one category: {{...}} and ${...} are both template_injection.
_ONE_CATEGORY_SAMPLE = "config {{user.name}} and path ${JAVA_HOME}/bin"


@pytest.mark.architecture
def test_a_single_category_reaches_the_default_threshold() -> None:
    result = detect_injection(_ONE_CATEGORY_SAMPLE)
    categories = {m["type"] for m in result["matches"]}
    assert categories == {"template_injection"}, categories
    assert result["risk_score"] >= DEFAULT_THRESHOLD, result["risk_score"]


@pytest.mark.architecture
def test_the_score_counts_patterns_not_categories() -> None:
    result = detect_injection(_ONE_CATEGORY_SAMPLE)
    categories = {m["type"] for m in result["matches"]}
    assert len(result["matches"]) > len(categories), (result["matches"], categories)


@pytest.mark.architecture
def test_most_categories_hold_more_than_one_pattern() -> None:
    counts = Counter(label for _, label in INJECTION_PATTERNS)
    multi = sorted(name for name, n in counts.items() if n > 1)
    assert "template_injection" in multi, multi
    assert len(multi) > len(counts) / 2, (multi, sorted(counts))


@pytest.mark.architecture
def test_the_guard_docstring_claims_no_two_category_agreement() -> None:
    if detect_injection(_ONE_CATEGORY_SAMPLE)["risk_score"] < DEFAULT_THRESHOLD:
        pytest.skip("scoring is per unique category now; the claim would be true")
    body = _GUARD.read_text(encoding="utf-8")
    assert "requires two independent" not in body, (
        "guard.py justifies the threshold with agreement between categories, "
        "which the arithmetic does not provide"
    )
