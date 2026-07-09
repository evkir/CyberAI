"""Agent-level wiring of halmos symbolic findings in SmartContractAgent.run."""

from __future__ import annotations

from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.halmos_tool import HalmosFinding
from cyberai.core.scan_session import ScanSession


def _agent() -> SmartContractAgent:
    agent = SmartContractAgent.__new__(SmartContractAgent)
    agent.AGENT_NAME = "web3"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.session = ScanSession(target="x")
    return agent


def _stub_static(monkeypatch):
    # Slither/aderyn find nothing; isolate the halmos path.
    empty = MagicMock()
    empty.available = False
    empty.analyze.return_value = []
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: empty)


def _fake_halmos(available, findings):
    tool = MagicMock()
    tool.available = available
    tool.analyze.return_value = findings
    return tool


def test_local_run_surfaces_halmos_keys(tmp_path, monkeypatch):
    _stub_static(monkeypatch)
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: _fake_halmos(False, []))
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    res = _agent().run(str(sol))
    assert res["halmos_findings"] == []
    assert res["halmos_available"] is False


def test_run_halmos_needs_project(tmp_path, monkeypatch):
    _stub_static(monkeypatch)
    cex = HalmosFinding(test_name="check_x()", contract="A.sol:A", exitcode=1, num_models=1)
    tool = _fake_halmos(True, [cex])
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: tool)
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    # No context -> no halmos_project -> tool.analyze never called.
    res = _agent().run(str(sol))
    assert res["halmos_findings"] == []
    tool.analyze.assert_not_called()


def test_counterexample_becomes_finding_and_severity(tmp_path, monkeypatch):
    _stub_static(monkeypatch)
    cex = HalmosFinding(
        test_name="check_noReentrancy(address)",
        contract="test/V.t.sol:VSymTest",
        exitcode=1,
        num_models=1,
        models=[{"path_id": 3, "result": "sat"}],
    )
    tool = _fake_halmos(True, [cex])
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: tool)
    sol = tmp_path / "V.sol"
    sol.write_text("contract V {}")
    res = _agent().run(str(sol), context={"halmos_project": "/proj", "halmos_contract": "VSymTest"})
    tool.analyze.assert_called_once_with("/proj", contract="VSymTest", loop=2)
    assert len(res["halmos_findings"]) == 1
    f = res["halmos_findings"][0]
    assert f["source"] == "halmos"
    assert f["test"] == "check_noReentrancy(address)"
    # A proven counterexample drives severity when static analysis is silent.
    assert res["highest_severity"] == "High"


def test_halmos_scan_tool_method(monkeypatch):
    tool = _fake_halmos(True, [HalmosFinding("check_x()", "A:A", 1, 1)])
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: tool)
    out = _agent()._halmos_scan("/proj")
    assert out["available"] is True
    assert out["count"] == 1
    assert out["findings"][0]["source"] == "halmos"
