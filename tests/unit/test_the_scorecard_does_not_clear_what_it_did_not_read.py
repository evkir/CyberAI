"""An unread stage prints `n/a`, not a clean INFO/0 row.

The scorecard is the artefact a reader takes away from a scan. Its rows are
`| category | severity | signals | source |`, and INFO with zero signals is a
statement: this was examined and nothing was found. A stage whose tool list
never arrived found nothing because it read nothing, and the two must not
render the same.
"""

from typing import Any

from cyberai.agents.mcp_scan.report import build_mcp_report
from cyberai.agents.mcp_scan.scorecard import build_mcp_scorecard


def _result(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "endpoint": "http://t/mcp",
        "transport": "http",
        "connected": True,
        "protocol_version": "2025-06-18",
        "tools": 0,
        "prompts": 0,
        "resources": 0,
        "error": None,
        "surface_errors": {},
        "poisoning": {"scanned": 0, "suspicious": 0, "tools": []},
        "overprivilege": {"scanned": 0, "overprivileged": 0, "tools": []},
        "exposure": {"exposed": False, "scan": {"severity": "INFO"}},
        "attestation": {"unauthenticated": False, "scan": {"severity": "INFO"}},
        "trust": {"scanned": 0, "shadowing": 0, "tools": []},
        "instructions": {"present": False, "is_finding": False, "scan": {}},
        "auth_metadata": {},
        "mst": [],
    }
    base.update(over)
    return base


_UNREAD = {
    "measured": False,
    "unread": "TimeoutError: slow",
    "scanned": None,
    "suspicious": None,
    "overprivileged": None,
    "shadowing": None,
    "tools": [],
}


def _row(card: str, category: str) -> list[str]:
    for line in card.splitlines():
        if line.startswith(f"| {category} |"):
            return [cell.strip() for cell in line.split("|")[1:-1]]
    raise AssertionError(f"no {category} row in\n{card}")


def test_a_measured_clean_scan_still_reads_zero() -> None:
    """Control: nothing found, and the scan says so with a number."""
    card = build_mcp_scorecard(_result())
    assert _row(card, "Tampering")[2] == "0"
    assert _row(card, "Information disclosure")[2] == "0"
    assert "tools probed: 0" in card


def test_an_unread_poisoning_stage_asserts_nothing() -> None:
    card = build_mcp_scorecard(_result(poisoning=dict(_UNREAD)))
    severity, signals = _row(card, "Tampering")[1], _row(card, "Tampering")[2]
    assert signals == "n/a", "a surface nobody read has no signal count"
    assert severity == "n/a", "nor a severity"


def test_an_unread_overprivilege_stage_does_not_sum_to_a_clean_row() -> None:
    card = build_mcp_scorecard(_result(overprivilege=dict(_UNREAD)))
    assert _row(card, "Information disclosure")[2] == "n/a"


def test_an_unread_trust_stage_leaves_the_other_elevation_signals_standing() -> None:
    """Attestation is read whatever the tool list did, so its finding survives."""
    card = build_mcp_scorecard(
        _result(
            trust=dict(_UNREAD),
            attestation={"unauthenticated": True, "scan": {"severity": "HIGH"}},
        )
    )
    row = _row(card, "Elevation of privilege")
    assert row[1] == "HIGH", "an unauthenticated endpoint is still a real finding"
    assert row[2] == "n/a", "but the count cannot include tools nobody listed"
    assert "surface not read" in row[3]


def test_the_header_says_the_tool_count_was_never_read() -> None:
    card = build_mcp_scorecard(_result(surface_errors={"tools": "TimeoutError: slow"}))
    assert "tools probed: not read" in card
    assert "tools probed: 0" not in card


def test_the_report_payload_does_not_report_zero_tools_probed() -> None:
    _markdown, data = build_mcp_report(
        _result(surface_errors={"tools": "TimeoutError: slow"}, poisoning=dict(_UNREAD))
    )
    assert data["tools_probed"] is None, "zero would read as a server with no tools"
    assert data["surface_errors"] == {"tools": "TimeoutError: slow"}


def test_the_report_payload_keeps_a_real_zero() -> None:
    _markdown, data = build_mcp_report(_result())
    assert data["tools_probed"] == 0
    assert data["surface_errors"] == {}
