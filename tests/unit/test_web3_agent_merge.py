"""Agent-level wiring of the slither+aderyn merge in SmartContractAgent.run."""

from __future__ import annotations

from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.aderyn_tool import parse_aderyn_json
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.slither_tool import parse_slither_json
from cyberai.core.scan_session import ScanSession


def _agent() -> SmartContractAgent:
    agent = SmartContractAgent.__new__(SmartContractAgent)
    agent.AGENT_NAME = "web3"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.session = ScanSession(target="x")
    return agent


def _mock_tools(monkeypatch, slither_json, aderyn_json, aderyn_available=True):
    fake_sl = MagicMock()
    fake_sl.available = True
    fake_sl.analyze.return_value = parse_slither_json(slither_json)
    fake_ad = MagicMock()
    fake_ad.available = aderyn_available
    fake_ad.analyze.return_value = parse_aderyn_json(aderyn_json) if aderyn_available else []
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: fake_sl)
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: fake_ad)


def test_run_merges_and_cross_validates(tmp_path, monkeypatch):
    sol = tmp_path / "Vault.sol"
    sol.write_text("contract V {}")
    _mock_tools(
        monkeypatch,
        '{"results":{"detectors":[{"check":"controlled-delegatecall","impact":"High",'
        '"confidence":"High","description":"d","id":"1"}]}}',
        '{"high_issues":{"issues":[{"title":"delegatecall in loop","description":"d",'
        '"detector_name":"delegatecall-in-loop","instances":[{}]}]}}',
    )
    res = _agent().run(str(sol))
    assert res["mode"] == "local"
    assert res["slither_available"] is True
    assert res["aderyn_available"] is True
    assert res["highest_severity"] == "Critical"
    swc112 = [m for m in res["merged_findings"] if m["swc"] == "SWC-112"]
    assert len(swc112) == 1
    assert swc112[0]["confidence"] == "cross-validated"
    assert set(swc112[0]["sources"]) == {"aderyn", "slither"}


def test_run_graceful_without_aderyn(tmp_path, monkeypatch):
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    _mock_tools(
        monkeypatch,
        '{"results":{"detectors":[{"check":"reentrancy-eth","impact":"High",'
        '"confidence":"Medium","description":"d","id":"1"}]}}',
        "",
        aderyn_available=False,
    )
    res = _agent().run(str(sol))
    assert res["aderyn_available"] is False
    assert res["aderyn_findings"] == []
    assert res["highest_severity"] == "Critical"  # slither-only still works
    assert len(res["merged_findings"]) == 1
    assert res["merged_findings"][0]["confidence"] == "single-tool"
