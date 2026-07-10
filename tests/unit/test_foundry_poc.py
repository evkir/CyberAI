"""Tests for the Foundry on-chain PoC runner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from cyberai.agents.web3.foundry_poc import (
    ForgePoCTool,
    PoCFinding,
    find_forge,
    parse_forge_test_json,
)
from cyberai.agents.web3.immunefi_severity import classify

_FIXTURE = Path(__file__).parent.parent / "fixtures" / "foundry_poc_report.json"


def test_parse_only_successful_exploits_surface():
    findings = parse_forge_test_json(_FIXTURE.read_text(encoding="utf-8"))
    # Two suites both define testExploit(); only the Success one is confirmed.
    assert len(findings) == 1
    f = findings[0]
    assert f.test_name == "testExploit()"
    assert f.contract == "test/Exploit.t.sol:ExploitTest"
    assert f.status == "Success"
    assert f.confirmed is True
    assert f.profit_wei == 4000000000000000000


def test_confirmed_poc_classifies_critical():
    # A replayed on-chain exploit is proof: High impact + High confidence ->
    # Critical via the immunefi fallback. Gated behind actual profit assertion.
    f = PoCFinding(test_name="testExploit()", contract="A.sol:A", status="Success")
    assert f.check == "onchain-poc-exploit"
    assert f.impact == "High"
    assert f.confidence == "High"
    assert classify(f) == "Critical"


def test_to_dict_tags_source():
    f = PoCFinding(test_name="testExploit()", contract="A.sol:A", status="Success", profit_wei=42)
    d = f.to_dict()
    assert d["source"] == "foundry"
    assert d["confirmed"] is True
    assert d["profit_wei"] == 42
    assert d["check"] == "onchain-poc-exploit"


def test_match_prefix_filters_non_exploit_tests():
    report = json.dumps(
        {
            "test/A.t.sol:A": {
                "test_results": {
                    "testSomethingElse()": {"status": "Success", "decoded_logs": []},
                    "testExploit()": {"status": "Success", "decoded_logs": []},
                }
            }
        }
    )
    findings = parse_forge_test_json(report)
    assert [f.test_name for f in findings] == ["testExploit()"]


def test_parse_empty_and_garbage():
    assert parse_forge_test_json("") == []
    assert parse_forge_test_json("{not json") == []
    assert parse_forge_test_json("[]") == []  # non-dict top level
    assert parse_forge_test_json("{}") == []
    # Malformed suite / results shapes are skipped, not fatal.
    assert parse_forge_test_json('{"s": {"test_results": []}}') == []


def test_find_forge_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "forge"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("FORGE_PATH", str(fake))
    assert find_forge() == str(fake)


def test_unavailable_run_is_graceful(monkeypatch):
    monkeypatch.delenv("FORGE_PATH", raising=False)
    with patch("cyberai.agents.web3.foundry_poc.shutil.which", return_value=None):
        with patch("cyberai.agents.web3.foundry_poc.os.path.exists", return_value=False):
            tool = ForgePoCTool()
            assert tool.available is False
            with patch("cyberai.agents.web3.foundry_poc.subprocess.run") as run:
                assert tool.run("some-project") == []
                run.assert_not_called()


def test_run_parses_confirmed_exploit(monkeypatch):
    tool = ForgePoCTool(forge_path="/opt/forge")

    class _Proc:
        stdout = _FIXTURE.read_text(encoding="utf-8")

    with patch("cyberai.agents.web3.foundry_poc.os.path.exists", return_value=True):
        with patch("cyberai.agents.web3.foundry_poc.subprocess.run", return_value=_Proc()) as run:
            findings = tool.run("proj", rpc_url="http://127.0.0.1:8545")
            cmd = run.call_args[0][0]
            assert "--fork-url" in cmd and "http://127.0.0.1:8545" in cmd
            assert "--json" in cmd and "--match-test" in cmd
    assert len(findings) == 1
    assert findings[0].confirmed is True
