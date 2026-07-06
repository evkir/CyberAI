"""Tests for Slither/aderyn finding merge with SWC cross-validation."""

from __future__ import annotations

from cyberai.agents.web3.aderyn_tool import AderynFinding
from cyberai.agents.web3.merge import DETECTOR_TO_SWC, merge_findings
from cyberai.agents.web3.slither_tool import SlitherFinding


def _sl(check, impact="High", confidence="High"):
    return SlitherFinding(
        check=check, impact=impact, confidence=confidence, description=f"{check} desc"
    )


def _ad(detector, severity="High"):
    return AderynFinding(
        detector_name=detector, title=detector, severity=severity, description=f"{detector} d"
    )


def test_cross_validation_same_swc_from_both_tools():
    # slither controlled-delegatecall and aderyn delegate-call-in-loop both map to SWC-112.
    merged = merge_findings([_sl("controlled-delegatecall")], [_ad("delegate-call-in-loop")])
    assert len(merged) == 1
    m = merged[0]
    assert m.swc == "SWC-112"
    assert m.confidence == "cross-validated"
    assert m.sources == ["aderyn", "slither"]
    assert set(m.checks) == {"controlled-delegatecall", "delegate-call-in-loop"}
    assert m.immunefi_severity == "Critical"  # worst across the group


def test_single_tool_findings_flagged():
    merged = merge_findings([_sl("reentrancy-eth")], [_ad("ecrecover", severity="Low")])
    by_swc = {m.swc: m for m in merged}
    assert by_swc["SWC-107"].confidence == "single-tool"
    assert by_swc["SWC-107"].sources == ["slither"]
    assert by_swc["SWC-117"].confidence == "single-tool"
    assert by_swc["SWC-117"].sources == ["aderyn"]


def test_unmapped_detector_kept_separate():
    merged = merge_findings([_sl("some-unknown-detector", impact="Low", confidence="Low")], [])
    assert len(merged) == 1
    assert merged[0].swc is None
    assert merged[0].confidence == "single-tool"
    assert merged[0].check == "some-unknown-detector"


def test_sorted_high_first_and_crossvalidated_ahead():
    merged = merge_findings(
        [_sl("controlled-delegatecall"), _sl("pragma", impact="Informational", confidence="High")],
        [_ad("delegate-call-in-loop")],
    )
    # Critical cross-validated delegatecall first, low-severity pragma last.
    assert merged[0].swc == "SWC-112"
    assert merged[0].confidence == "cross-validated"
    assert merged[-1].swc == "SWC-103"


def test_swc_map_covers_verified_aderyn_names():
    assert DETECTOR_TO_SWC["delegate-call-in-loop"] == "SWC-112"
    assert DETECTOR_TO_SWC["ecrecover"] == "SWC-117"


def test_empty_inputs():
    assert merge_findings([], []) == []
