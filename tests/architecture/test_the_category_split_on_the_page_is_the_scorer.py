"""The research page counts categories the way the scorer counts them.

`score_injection` sums `CATEGORY_WEIGHTS` over the distinct categories a text
hits, which is why a pattern added to a category already covered changes no
score. docs/research/detector-v2.md explains that rule and counts the
categories holding more than one pattern, because that count is the whole
reason the scorer stopped multiplying matches.

The count was spelled out and nothing read it. A category split in two, or a
lone pattern joined by a second, moves it silently, and the paragraph would go
on describing a scorer the tree no longer has -- the same failure this page
was written to record, one release later.

The weight table above the paragraph is held here too, by membership rather
than by its numbers: the page names which categories are directive and which
are structural, and a category that changed sides would leave both tiers
reading plausibly.
"""

import collections
import pathlib
import re

from cyberai.core.security.injection_detector import (
    CATEGORY_WEIGHTS,
    DIRECTIVE_WEIGHT,
    INJECTION_PATTERNS,
    STRUCTURAL_WEIGHT,
)

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PAGE = _ROOT / "docs" / "research" / "detector-v2.md"


def _page() -> str:
    return _PAGE.read_text(encoding="utf-8")


def _tier(weight: int) -> set[str]:
    return {name for name, value in CATEGORY_WEIGHTS.items() if value == weight}


def test_the_page_counts_the_categories_that_hold_more_than_one_pattern() -> None:
    counts = collections.Counter(category for _, category in INJECTION_PATTERNS)
    multi = sum(1 for seen in counts.values() if seen > 1)
    match = re.search(r"(\d+) of the (\d+) categories hold\n?\s*more than one pattern", _page())
    assert match, "the page no longer counts the multi-pattern categories in digits"
    assert int(match.group(1)) == multi, (match.group(1), multi)
    assert int(match.group(2)) == len(counts), (match.group(2), len(counts))


def test_every_category_the_scorer_weighs_is_on_the_page_in_its_own_tier() -> None:
    body = _page()
    directive = body[
        body.index("| 50 (directive) |") : body.index("\n", body.index("| 50 (directive) |"))
    ]
    structural = body[
        body.index("| 10 (structural) |") : body.index("\n", body.index("| 10 (structural) |"))
    ]
    for name in _tier(DIRECTIVE_WEIGHT):
        assert name in directive, (
            f"{name} scores {DIRECTIVE_WEIGHT} and is not in the directive row"
        )
        assert name not in structural, f"{name} is listed as structural"
    for name in _tier(STRUCTURAL_WEIGHT):
        assert name in structural, (
            f"{name} scores {STRUCTURAL_WEIGHT} and is not in the structural row"
        )
        assert name not in directive, f"{name} is listed as directive"


def test_the_page_names_no_category_the_scorer_does_not_weigh() -> None:
    body = _page()
    rows = body[
        body.index("| 50 (directive) |") : body.index("\n\n", body.index("| 10 (structural) |"))
    ]
    cells = [row.split("|")[2] for row in rows.splitlines() if row.startswith("|")]
    named = {name.strip() for cell in cells for name in cell.split(",")}
    assert named == set(CATEGORY_WEIGHTS), sorted(named ^ set(CATEGORY_WEIGHTS))
