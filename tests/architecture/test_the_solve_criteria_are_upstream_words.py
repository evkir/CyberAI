"""The benchmark page names the solve criteria in the adapter's own words.

`cyberai/bench/cve_bench.py` holds `UPSTREAM_CRITERIA` verbatim off the upstream
one-day prompt and says in a comment that a paraphrase of it silently describes
the previous release. `test_the_bench_answers_to_the_upstream.py` holds the
constant against a byte-for-byte snapshot of that prompt, so the adapter cannot
drift from upstream unnoticed.

The public page had no such guard and had already drifted: it listed the eight
in an order of its own, spelled `unauthorised` in British English, and
described `outbound service` as an outbound request from the server. Every one
of those reads plausibly, which is exactly why nothing caught them.

So the page quotes the constant rather than retelling it, and this file holds
that. The count is a digit because the tree answers it: a criterion added or
dropped upstream moves `len(UPSTREAM_CRITERIA)` and reds the sentence that
says how many there are.
"""

import pathlib
import re

from cyberai.bench.cve_bench import UPSTREAM_CRITERIA

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PAGE = _ROOT / "docs" / "benchmarks" / "cve-bench.md"
_OPENING = "A solve is credited by any of"


def _claim() -> str:
    """The paragraph naming the criteria, which is the only place they are listed."""
    body = _PAGE.read_text(encoding="utf-8")
    start = body.index(_OPENING)
    return body[start : body.index("\n\n", start)]


def test_the_page_names_every_criterion_upstream_names() -> None:
    claim = _claim()
    missing = [label for label in UPSTREAM_CRITERIA if label not in claim]
    assert not missing, f"the page does not carry upstream's words for: {missing}"


def test_the_page_lists_them_in_the_order_the_adapter_holds() -> None:
    claim = _claim()
    positions = [claim.find(label) for label in UPSTREAM_CRITERIA]
    assert all(place >= 0 for place in positions), dict(zip(UPSTREAM_CRITERIA, positions))
    assert positions == sorted(positions), dict(zip(UPSTREAM_CRITERIA, positions))


def test_the_count_is_a_digit_the_tree_answers() -> None:
    claim = _claim()
    match = re.search(rf"{re.escape(_OPENING)} (\d+) outcomes", claim)
    assert match, f"the page does not count the outcomes in digits: {claim[:80]}"
    assert int(match.group(1)) == len(UPSTREAM_CRITERIA), match.group(1)
