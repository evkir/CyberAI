"""Detector names in our tables must exist in the aderyn registry.

Seven SWC keys and sixteen severity keys did not: plausible-looking names no
finding could ever carry, so the mapping was dead on arrival and the audit
silently lost the classification. The registry of aderyn 0.1.9 is snapshotted
beside this test; the live binary is checked separately under the smoke marker.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberai.agents.web3.immunefi_severity import (
    ADERYN_CHECK_TO_IMMUNEFI,
    CHECK_TO_IMMUNEFI,
)
from cyberai.agents.web3.merge import ADERYN_DETECTOR_SWC, DETECTOR_TO_SWC

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "aderyn_registry_0.1.9.json"

# Names shipped by earlier releases that `aderyn registry` never listed.
KNOWN_GHOSTS = {
    "reentrancy-state-change",
    "non-reentrant-not-first",
    "delegatecall-in-loop",
    "unchecked-low-level-call",
    "eth-send-unchecked-address",
    "selfdestruct",
    "builtin-symbol-shadowing",
    "function-selector-collision",
    "unsafe-casting",
    "strict-equality-contract-balance",
    "unsafe-erc20-operation",
    "incorrect-erc20-interface",
    "incorrect-erc721-interface",
    "todo",
    "unused-import",
    "unused-state-variable",
}


@pytest.fixture(scope="module")
def registry() -> dict:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))["detectors"]
    # An empty reference makes every membership check vacuously true. Assert the
    # reference exists before comparing anything against it.
    assert len(data) == 63, len(data)
    return data


def test_swc_table_uses_registry_names(registry):
    unknown = sorted(k for k in ADERYN_DETECTOR_SWC if k not in registry)
    assert unknown == []


def test_severity_table_uses_registry_names(registry):
    unknown = sorted(k for k in ADERYN_CHECK_TO_IMMUNEFI if k not in registry)
    assert unknown == []


def test_no_ghost_name_comes_back(registry):
    assert KNOWN_GHOSTS.isdisjoint(ADERYN_DETECTOR_SWC)
    assert KNOWN_GHOSTS.isdisjoint(ADERYN_CHECK_TO_IMMUNEFI)
    assert KNOWN_GHOSTS.isdisjoint(registry)


def test_every_mapped_swc_detector_also_has_a_tier():
    """A detector with an SWC but no tier silently falls back to impact heuristics."""
    missing = sorted(k for k in ADERYN_DETECTOR_SWC if k not in CHECK_TO_IMMUNEFI)
    assert missing == []


def test_reentrancy_is_unreachable_from_aderyn(registry):
    """aderyn 0.1.9 ships no reentrancy detector — SWC-107 is slither-only."""
    assert [d for d in registry if d.startswith("reentrancy")] == []
    swc_107 = {k for k, v in ADERYN_DETECTOR_SWC.items() if v == "SWC-107"}
    assert swc_107 == {"non-reentrant-before-others"}


def test_send_ether_no_checks_is_mapped():
    """The one High detector our fixture raises used to map to nothing at all."""
    assert DETECTOR_TO_SWC["send-ether-no-checks"] == "SWC-105"
    assert CHECK_TO_IMMUNEFI["send-ether-no-checks"] == "High"
