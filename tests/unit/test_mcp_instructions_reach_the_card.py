"""A steering initialize reply must not leave the published card clean.

The stage itself is pinned next door. What is pinned here is the wiring to the
three places a reader actually looks: the STRIDE scorecard, the risk-row table,
and the severity histogram beside it. Each was a list of stages named by hand,
so a stage reached none of them by being written.

Measured on the fixture stand before the wiring existed: zero tools, a directive
naming a tool the server does not advertise, and six INFO rows. The histogram
was the last to be found -- the table already carried a HIGH row while the count
above it read zero.

The clean half of every assertion is the control. A server that sends no
instructions must score exactly as it did before this stage existed, or the
wiring is inflating someone else's verdict rather than reporting its own.
"""

from __future__ import annotations

from typing import Any

from cyberai.agents.mcp_scan.report import build_mcp_report, build_risk_rows
from cyberai.agents.mcp_scan.scorecard import build_mcp_scorecard

_STEERING: dict[str, Any] = {
    "present": True,
    "is_finding": True,
    "scan": {"severity": "HIGH", "unadvertised_tools": ["exfiltrate_secrets"]},
}
_SILENT: dict[str, Any] = {"present": False, "is_finding": False, "scan": {"severity": "INFO"}}
# The common case in the field, and the only input that tells the two flags
# apart: the server sent instructions and they are ordinary prose. Without
# it, a reader keyed on "present" instead of "is_finding" scores every
# talkative server as a finding and no assertion here notices.
_PLAIN: dict[str, Any] = {"present": True, "is_finding": False, "scan": {"severity": "INFO"}}


def _result(instructions: dict[str, Any]) -> dict[str, Any]:
    """A scan of a server with no tools at all -- every other stage is clean."""
    return {
        "endpoint": "stdio://stand",
        "transport": "stdio",
        "connected": True,
        "tools": 0,
        "poisoning": {"scanned": 0, "suspicious": 0, "tools": []},
        "overprivilege": {"scanned": 0, "overprivileged": 0, "tools": []},
        "exposure": {"exposed": False, "scan": {}},
        "attestation": {"unauthenticated": False, "scan": {}},
        "trust": {"scanned": 0, "shadowing": 0, "tools": []},
        "instructions": instructions,
        "auth_metadata": {},
        "mst": [],
    }


def _row(card: str, category: str) -> list[str]:
    line = next(line for line in card.splitlines() if line.startswith(f"| {category} |"))
    return [cell.strip() for cell in line.split("|")[1:-1]]


def test_a_steering_server_does_not_score_clean_on_every_category() -> None:
    """What this does not separate: severity and signal count are one tuple here,
    so a mutant dropping either term from the Elevation arithmetic dies on this
    same assertion. Which of the two broke is read from the failure, not from
    which test went red.
    """
    card = build_mcp_scorecard(_result(_STEERING))
    _, severity, signals, _ = _row(card, "Elevation of privilege")
    assert (severity, signals) == ("HIGH", "1")


def test_a_silent_server_leaves_elevation_where_it_was() -> None:
    """Control: with no instructions the category reports what the others say."""
    card = build_mcp_scorecard(_result(_SILENT))
    _, severity, signals, _ = _row(card, "Elevation of privilege")
    assert (severity, signals) == ("INFO", "0")


def test_the_category_names_the_stage_that_can_raise_it() -> None:
    """A reader who sees the row has to be able to find out what produced it.

    The phrase is asserted, not the stage name: the source already ends with a
    parenthesised list of stages, so matching "instructions" alone passes on
    text that describes none of what this stage does.
    """
    card = build_mcp_scorecard(_result(_STEERING))
    *_, source = _row(card, "Elevation of privilege")
    assert "server instructions summoning an unadvertised tool" in source


def test_the_risk_table_carries_a_row_for_the_stage() -> None:
    rows = {row.stage: row for row in build_risk_rows(_result(_STEERING))}
    assert "server-instructions" in rows
    assert (rows["server-instructions"].severity, rows["server-instructions"].signals) == (
        "HIGH",
        1,
    )


def test_a_silent_server_still_gets_the_row_at_rest() -> None:
    """Absent is not the same answer as unexamined: the row stays, at INFO."""
    rows = {row.stage: row for row in build_risk_rows(_result(_SILENT))}
    assert "server-instructions" in rows
    assert rows["server-instructions"].signals == 0


def test_ordinary_instructions_are_not_a_signal() -> None:
    """Control: the row counts findings, not whether the server said anything.

    A mutant reading "present" where it should read "is_finding" survives every
    other assertion in this file, because the two flags agree on both of the
    other fixtures.
    """
    rows = {row.stage: row for row in build_risk_rows(_result(_PLAIN))}
    assert rows["server-instructions"].signals == 0
    card = build_mcp_scorecard(_result(_PLAIN))
    _, severity, signals, _ = _row(card, "Elevation of privilege")
    assert (severity, signals) == ("INFO", "0")
    _, meta = build_mcp_report(_result(_PLAIN))
    assert sum(meta["severity_summary"].values()) == 0


def test_the_histogram_counts_what_the_table_shows() -> None:
    """The count and the row are two renderings of one finding, not two facts."""
    _, meta = build_mcp_report(_result(_STEERING))
    assert meta["severity_summary"]["HIGH"] == 1


def test_the_histogram_stays_empty_for_a_silent_server() -> None:
    _, meta = build_mcp_report(_result(_SILENT))
    assert sum(meta["severity_summary"].values()) == 0
