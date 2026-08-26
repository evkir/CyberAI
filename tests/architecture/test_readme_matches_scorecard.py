"""README's run-metrics table must be the committed agent scorecard.

CJ in the private tail list. The published card lagged the code by two days:
it showed 28 requests where a run after decontamination produced 21, and
nothing failed. docs/benchmarks/local-suite.md already states the rule --
these numbers come from a measured run, never by hand -- but a rule written
in prose gates nothing. The same figures now live in README as well, which
doubles the surface a stale number can hide on.

So this compares the two documents cell by cell rather than checking a
format. README drops the availability column, which the card carries and the
prose covers in words; every other cell must match, in the same task order.
Emphasis markers are stripped before comparing, because README bolds its
total and the card does not -- that is presentation, not measurement.

What this does not do is re-run the bench. A test that shells out to Docker
is not an architecture test, and the card is the artifact of a real run by
construction: regenerating it is what `--scorecard` is for. The gate is on
the gap between the artifact and the prose that quotes it, which is exactly
where the drift happened.
"""

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_CARD = _ROOT / "examples/local-bench/scorecard-agent.md"


def _cells(line: str) -> list[str]:
    return [c.strip().replace("*", "") for c in line.strip()[1:-1].split("|")]


def _tables(text: str) -> list[list[list[str]]]:
    """Every markdown pipe-table in the document, header row included."""
    tables: list[list[list[str]]] = []
    current: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("|"):
            current.append(_cells(line))
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables


def _only(text: str, *, has: str, lacks: str | None = None) -> list[list[str]]:
    found = [t for t in _tables(text) if has in t[0] and (lacks is None or lacks not in t[0])]
    assert len(found) == 1, [t[0] for t in found]
    return found[0]


def test_readme_run_metrics_match_the_committed_agent_scorecard() -> None:
    card = _only(_CARD.read_text(encoding="utf-8"), has="available")
    readme = _only(_README.read_text(encoding="utf-8"), has="in-band", lacks="available")

    # Drop the separator row and the availability column the card alone carries.
    card_rows = [r[:1] + r[2:] for r in card if set(r[0]) != {"-"}]
    readme_rows = [r for r in readme if set(r[0]) != {"-"}]

    assert readme_rows[1:] == card_rows[1:], (readme_rows, card_rows)
