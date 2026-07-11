"""Privilege-escalation path finder and agent wiring for access-control."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.access_control import _paths_for_model, find_escalation_paths
from cyberai.agents.web3.access_graph import parse_contracts
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.core.scan_session import ScanSession

FIXTURE = Path(__file__).parent.parent / "fixtures" / "access_control.sol"


def test_escalation_path_setowner_unlocks_guarded():
    paths = find_escalation_paths(FIXTURE.read_text())
    entries = {p.entry for p in paths}
    assert "setOwner" in entries
    p = next(p for p in paths if p.entry == "setOwner")
    assert p.grants == "ownership"
    assert "withdrawAll" in p.unlocks
    assert p.to_dict()["source"] == "access-control"


def test_no_path_without_unlockable_targets():
    src = """
    contract C {
        address owner;
        function setOwner(address o) external { owner = o; }
    }
    """
    assert _paths_for_model(parse_contracts(src)[0]) == []


def test_non_ownership_entry_ignored():
    src = """
    contract C {
        uint256 x;
        function poke() external { x = 1; }
        function admin_op() external onlyOwner { x = 2; }
    }
    """
    assert _paths_for_model(parse_contracts(src)[0]) == []


def _agent() -> SmartContractAgent:
    a = SmartContractAgent.__new__(SmartContractAgent)
    a.AGENT_NAME = "web3"
    a._log = MagicMock()
    a.kb = MagicMock()
    a.session = ScanSession(target="x")
    a.tools = {}
    a._register_tools()
    return a


def _mute_tools(monkeypatch):
    empty = MagicMock()
    empty.available = False
    empty.analyze.return_value = []
    empty.run.return_value = []
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "ForgePoCTool", lambda *a, **k: empty)


def test_agent_surfaces_access_findings_and_severity(monkeypatch):
    _mute_tools(monkeypatch)
    res = _agent().run(str(FIXTURE))
    checks = {f["check"] for f in res["access_findings"]}
    assert "missing-auth" in checks
    assert "unprotected-initializer" in checks
    assert "controlled-delegatecall" in checks
    assert res["highest_severity"] == "Critical"
    assert any(p["entry"] == "setOwner" for p in res["escalation_paths"])


def test_agent_access_scan_tool(monkeypatch):
    out = _agent()._access_scan(str(FIXTURE))
    assert out["count"] >= 3
    assert any(p["entry"] == "setOwner" for p in out["escalation_paths"])
