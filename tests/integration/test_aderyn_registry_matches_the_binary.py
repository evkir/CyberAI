"""The snapshotted aderyn registry must answer to the binary, not to itself.

tests/unit/test_web3_detector_names.py checks our SWC and severity tables
against a snapshot of `aderyn registry`. Nothing checked the snapshot against
the installed binary, so an aderyn upgrade that renames or reclassifies a
detector would leave every test green while the mapping went dead again.

The live comparison needs the binary, which CI does not install, so it carries
the smoke marker and skips when aderyn is absent. In CI it therefore always
skips: it is a developer-machine guard, not a pipeline one. The parser is
covered separately so the shape of the comparison stays under the normal gate.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from cyberai.agents.web3.aderyn_tool import find_aderyn

SNAPSHOT = Path(__file__).resolve().parents[1] / "fixtures" / "aderyn_registry_0.1.9.json"

# `aderyn registry` prints "<name><padding>- <Title>" rows grouped under bare
# rating headers. Measured against 0.1.9: 77 lines, 63 rows, two headers.
_ROW = re.compile(r"^(\S+)\s+-\s")
_HEADER = re.compile(r"^(Critical|High|Medium|Low)$")

SAMPLE = """
Detector Registry

Name                             Title (Rating)

Low

centralization-risk            - Centralization Risk for trusted owners
ecrecover                      - Use of ecrecover

High

rtlo                           - Right-To-Left-Override character
"""


def parse_registry(text: str) -> dict[str, str]:
    """Map detector name to the rating section it was printed under."""
    detectors: dict[str, str] = {}
    section: str | None = None
    for line in text.splitlines():
        header = _HEADER.match(line.strip())
        if header and not _ROW.match(line):
            section = header.group(1)
            continue
        row = _ROW.match(line)
        if row:
            detectors[row.group(1)] = section or ""
    return detectors


def load_snapshot() -> dict[str, str]:
    data: dict[str, str] = json.loads(SNAPSHOT.read_text(encoding="utf-8"))["detectors"]
    return data


def test_the_parser_reads_names_and_the_rating_above_them():
    """A name-only pattern would swallow the headers and the column title."""
    parsed = parse_registry(SAMPLE)
    assert parsed == {
        "centralization-risk": "Low",
        "ecrecover": "Low",
        "rtlo": "High",
    }


def test_the_snapshot_is_the_size_that_was_measured():
    """An empty or shrunken reference makes every comparison below vacuous."""
    snapshot = load_snapshot()
    assert len(snapshot) == 63, len(snapshot)
    ratings = sorted(snapshot.values())
    assert ratings.count("High") == 36, ratings.count("High")
    assert ratings.count("Low") == 27, ratings.count("Low")


@pytest.mark.smoke
def test_the_snapshot_matches_the_installed_binary():
    """Names and ratings both: a reclassified detector is as dead as a renamed one."""
    binary = find_aderyn()
    if binary is None:
        pytest.skip("aderyn is not installed on this machine")

    proc = subprocess.run(
        [binary, "registry"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr[:400])

    live = parse_registry(proc.stdout)
    snapshot = load_snapshot()
    assert len(snapshot) == 63, len(snapshot)
    assert len(live) == 63, (len(live), sorted(live)[:5])

    assert sorted(live) == sorted(snapshot), {
        "only_in_binary": sorted(set(live) - set(snapshot)),
        "only_in_snapshot": sorted(set(snapshot) - set(live)),
    }
    reclassified = {k: (live[k], snapshot[k]) for k in snapshot if live[k] != snapshot[k]}
    assert reclassified == {}
