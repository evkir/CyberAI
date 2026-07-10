"""Agent-level wiring of Foundry on-chain PoC findings in SmartContractAgent.run."""

from __future__ import annotations

from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.foundry_poc import PoCFinding
from cyberai.core.scan_session import ScanSession


def _agent() -> SmartContractAgent:
    agent = SmartContractAgent.__new__(SmartContractAgent)
    agent.AGENT_NAME = "web3"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.session = ScanSession(target="x")
    return agent


def _stub_static(monkeypatch):
    empty = MagicMock()
    empty.available = False
    empty.analyze.return_value = []
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: empty)


def _fake_forge(available, findings):
    tool = MagicMock()
    tool.available = available
    tool.run.return_value = findings
    return tool


def test_local_run_surfaces_poc_keys(tmp_path, monkeypatch):
    _stub_static(monkeypatch)
    monkeypatch.setattr(ag, "ForgePoCTool", lambda *a, **k: _fake_forge(False, []))
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    res = _agent().run(str(sol))
    assert res["poc_findings"] == []
    assert res["poc_available"] is False


def test_poc_needs_project(tmp_path, monkeypatch):
    _stub_static(monkeypatch)
    confirmed = PoCFinding(test_name="testExploit()", contract="A:A", status="Success")
    tool = _fake_forge(True, [confirmed])
    monkeypatch.setattr(ag, "ForgePoCTool", lambda *a, **k: tool)
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    # No context -> no foundry_project -> tool.run never called.
    res = _agent().run(str(sol))
    assert res["poc_findings"] == []
    tool.run.assert_not_called()


def test_confirmed_poc_drives_critical_severity(tmp_path, monkeypatch):
    _stub_static(monkeypatch)
    confirmed = PoCFinding(
        test_name="testExploit()",
        contract="test/V.t.sol:VExploit",
        status="Success",
        profit_wei=4000000000000000000,
    )
    tool = _fake_forge(True, [confirmed])
    monkeypatch.setattr(ag, "ForgePoCTool", lambda *a, **k: tool)
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    res = _agent().run(
        str(sol),
        context={"foundry_project": "/proj", "fork_rpc": "http://127.0.0.1:8545"},
    )
    tool.run.assert_called_once_with("/proj", rpc_url="http://127.0.0.1:8545", match="testExploit")
    assert len(res["poc_findings"]) == 1
    f = res["poc_findings"][0]
    assert f["source"] == "foundry"
    assert f["confirmed"] is True
    # A confirmed on-chain exploit drives severity to Critical.
    assert res["highest_severity"] == "Critical"


def test_synthesize_poc_tool_method():
    out = _agent()._synthesize_poc({"check": "reentrancy-eth", "target_fn": "withdraw"}, "Vault")
    assert "function testExploit() public" in out["script"]
