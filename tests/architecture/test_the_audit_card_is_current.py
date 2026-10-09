"""The committed MCP audit card must still be what a scan produces.

A card in examples/ is the one artifact of this scanner a reader outside the
project can check, and it is a photograph: it keeps saying what the scanner
found on the morning it ran, long after the scanner stopped saying it. That
already happened once to a bench card, which published twenty-eight requests
against code that had come to send twenty-one, and no gate noticed.

This one runs the scan rather than comparing two documents, because there is
no second document to compare against: README quotes the bench cards and
nothing quotes this one, so the only statement of what the scanner finds is
the scan itself.

The price, measured rather than guessed: 3.96 seconds, two child processes
and two stdio handshakes, against a suite that runs in about 175. It is not
marked slow -- that marker means real network calls in this repository, and
borrowing it for a local subprocess would make the marker mean two things.

What this pins: the findings, their severities, the evidence behind each
flag, and the prose the writer wraps around them. What it does not pin: the
timestamp, which moves on every run and is dropped on both sides. A scan that
reaches the network is a different failure and would fail here as a diff
rather than as a diagnosis, so the message says where to look.
"""

import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CARD = _ROOT / "examples" / "mcp-audit" / "own-servers.md"
_WRITER = _ROOT / "scripts" / "mcp_audit_artifact.py"
_REGENERATE = "python3 scripts/mcp_audit_artifact.py examples/mcp-audit/own-servers.md"


def _without_timestamp(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.startswith("| timestamp |")]


@pytest.mark.unit
def test_the_card_and_its_writer_exist() -> None:
    assert _CARD.is_file(), f"the published audit card is gone; {_REGENERATE}"
    assert _WRITER.is_file(), "the writer the card names as its source is gone"


@pytest.mark.unit
def test_the_committed_card_matches_a_fresh_scan(tmp_path: pathlib.Path) -> None:
    fresh = tmp_path / "own-servers.md"
    completed = subprocess.run(
        [sys.executable, str(_WRITER), str(fresh)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr

    assert _without_timestamp(fresh.read_text(encoding="utf-8")) == _without_timestamp(
        _CARD.read_text(encoding="utf-8")
    ), f"the card no longer matches what the scanner finds; {_REGENERATE}"
