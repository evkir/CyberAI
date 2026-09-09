"""Tests for the aderyn Solidity static-analysis wrapper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from cyberai.agents.web3.aderyn_tool import (
    AderynFinding,
    AderynTool,
    find_aderyn,
    parse_aderyn_json,
)

_FIXTURE = Path(__file__).parent.parent / "fixtures" / "aderyn_report.json"


def test_parse_fixture_report():
    findings = parse_aderyn_json(_FIXTURE.read_text(encoding="utf-8"))
    assert [f.detector_name for f in findings] == ["delegate-call-in-loop", "ecrecover"]
    high, low = findings
    assert high.severity == "High"
    assert high.instances == 1
    assert low.severity == "Low"
    assert low.instances == 2  # two instances in the fixture


def test_finding_is_classify_compatible():
    # AderynFinding exposes .check/.impact/.confidence like SlitherFinding, so
    # immunefi.classify can consume it via the fallback table. ecrecover no
    # longer proves that — it has an explicit tier now, so the precise table
    # would answer and the fallback would never run. yul-return is a real
    # aderyn 0.1.9 detector with no tier of its own.
    from cyberai.agents.web3.immunefi_severity import CHECK_TO_IMMUNEFI, classify

    f = AderynFinding(detector_name="yul-return", title="t", severity="High", description="d")
    assert f.check == "yul-return"
    assert f.impact == "High"
    assert f.confidence == "Medium"
    assert "yul-return" not in CHECK_TO_IMMUNEFI
    assert classify(f) == "High"  # ("High","Medium") fallback


def test_to_dict_tags_source():
    f = AderynFinding(detector_name="x", title="t", severity="Low", description="d", instances=3)
    d = f.to_dict()
    assert d["source"] == "aderyn"
    assert d["check"] == "x"
    assert d["instances"] == 3


def test_parse_empty_and_garbage():
    assert parse_aderyn_json("") == []
    assert parse_aderyn_json("{not json") == []
    assert parse_aderyn_json("{}") == []


def test_find_aderyn_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "aderyn"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("ADERYN_PATH", str(fake))
    assert find_aderyn() == str(fake)


def test_available_false_and_analyze_graceful(monkeypatch):
    monkeypatch.delenv("ADERYN_PATH", raising=False)
    with patch("cyberai.agents.web3.aderyn_tool.shutil.which", return_value=None):
        with patch("cyberai.agents.web3.aderyn_tool.os.path.exists", return_value=False):
            tool = AderynTool()
            assert tool.available is False
            with patch("cyberai.agents.web3.aderyn_tool.subprocess.run") as run:
                assert tool.analyze("Vault.sol") == []
                run.assert_not_called()
