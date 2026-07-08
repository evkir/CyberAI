"""Tests for the halmos symbolic-execution wrapper."""

from __future__ import annotations

import json
from unittest.mock import patch

from cyberai.agents.web3.halmos_tool import (
    COUNTEREXAMPLE,
    HalmosFinding,
    HalmosTool,
    find_halmos,
    parse_halmos_json,
)

# Minimal halmos --json-output shape (verified against the 0.3.x result model):
# one counterexample (exitcode 1) plus one passing test (exitcode 0).
_REPORT = json.dumps(
    {
        "exitcode": 1,
        "test_results": {
            "test/Vault.t.sol:VaultTest": [
                {
                    "name": "check_noReentrancy(address)",
                    "exitcode": 1,
                    "num_models": 1,
                    "models": [{"path_id": 3, "result": "sat"}],
                    "num_paths": [5, 4, 1],
                    "time": [2, 1, 1],
                    "num_bounded_loops": 0,
                },
                {
                    "name": "check_balanceInvariant(uint256)",
                    "exitcode": 0,
                    "num_models": 0,
                    "models": None,
                    "num_paths": [3, 3, 0],
                    "time": [1, 1, 0],
                    "num_bounded_loops": 0,
                },
            ]
        },
    }
)


def test_parse_only_counterexamples_are_findings():
    findings = parse_halmos_json(_REPORT)
    # Only the exitcode==1 test is a finding; the passing test is dropped.
    assert len(findings) == 1
    f = findings[0]
    assert f.test_name == "check_noReentrancy(address)"
    assert f.contract == "test/Vault.t.sol:VaultTest"
    assert f.exitcode == COUNTEREXAMPLE
    assert f.num_models == 1
    assert f.models == [{"path_id": 3, "result": "sat"}]


def test_finding_is_classify_compatible():
    # HalmosFinding exposes .check/.impact/.confidence like the other tools,
    # so immunefi.classify consumes it via the fallback table.
    f = HalmosFinding(test_name="check_x()", contract="A.sol:A", exitcode=1, num_models=1)
    assert f.check == "symbolic-counterexample"
    assert f.impact == "Medium"
    assert f.confidence == "High"
    from cyberai.agents.web3.immunefi_severity import classify

    # ("Medium","High") fallback -> High: a proven break, conservatively rated.
    assert classify(f) == "High"


def test_to_dict_tags_source():
    f = HalmosFinding(test_name="check_x()", contract="A.sol:A", exitcode=1, num_models=2)
    d = f.to_dict()
    assert d["source"] == "halmos"
    assert d["test"] == "check_x()"
    assert d["num_models"] == 2


def test_parse_empty_and_garbage():
    assert parse_halmos_json("") == []
    assert parse_halmos_json("{not json") == []
    assert parse_halmos_json("{}") == []
    assert parse_halmos_json('{"test_results": []}') == []  # non-dict results


def test_find_halmos_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "halmos"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("HALMOS_PATH", str(fake))
    assert find_halmos() == str(fake)


def test_available_false_and_analyze_graceful(monkeypatch):
    monkeypatch.delenv("HALMOS_PATH", raising=False)
    with patch("cyberai.agents.web3.halmos_tool.shutil.which", return_value=None):
        with patch("cyberai.agents.web3.halmos_tool.os.path.exists", return_value=False):
            tool = HalmosTool()
            assert tool.available is False
            with patch("cyberai.agents.web3.halmos_tool.subprocess.run") as run:
                assert tool.analyze("my-foundry-project") == []
                run.assert_not_called()
