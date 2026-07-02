"""SmartContractAgent e2e: reentrant fixture -> slither -> Critical."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.immunefi_severity import classify_all, highest_tier
from cyberai.agents.web3.slither_tool import SlitherTool, parse_slither_json

FIXTURE = Path(__file__).parent.parent / "fixtures" / "dao_reentrant.sol"

# Slither requires the binary + solc; skip the live runs when unavailable.
_slither_available = SlitherTool().available
requires_slither = pytest.mark.skipif(not _slither_available, reason="slither binary not installed")


def _agent() -> SmartContractAgent:
    agent = SmartContractAgent.__new__(SmartContractAgent)
    agent.AGENT_NAME = "web3"
    agent._log = MagicMock()
    agent.kb = MagicMock()
    agent.audit = MagicMock()
    agent.tools = {}
    agent._register_tools()
    return agent


def test_fixture_exists():
    assert FIXTURE.exists(), "reentrant fixture missing"
    assert "withdraw" in FIXTURE.read_text()


# ── mocked pipeline (always runs, no binary needed) ───────────────────


def test_classification_pipeline_mocked():
    """slither JSON (canned) -> classify -> Critical reentrancy."""
    canned = (
        '{"success":true,"error":null,"results":{"detectors":['
        '{"check":"reentrancy-eth","impact":"High","confidence":"Medium",'
        '"description":"Reentrancy in DAOReentrant.withdraw()","id":"r1"},'
        '{"check":"low-level-calls","impact":"Informational","confidence":"High",'
        '"description":"Low level call","id":"l1"},'
        '{"check":"solc-version","impact":"Informational","confidence":"High",'
        '"description":"solc","id":"s1"}'
        "]}}"
    )
    findings = parse_slither_json(canned)
    assert len(findings) == 3
    rows = classify_all(findings)
    assert rows[0]["immunefi_severity"] == "Critical"
    assert rows[0]["check"] == "reentrancy-eth"
    assert highest_tier(findings) == "Critical"


def test_agent_run_mocked(monkeypatch):
    """SmartContractAgent.run on a local .sol with slither mocked."""
    import cyberai.agents.web3.agent as ag

    fake_tool = MagicMock()
    fake_tool.available = True
    fake_tool.analyze.return_value = parse_slither_json(
        '{"results":{"detectors":[{"check":"reentrancy-eth","impact":"High",'
        '"confidence":"Medium","description":"Reentrancy","id":"r1"}]}}'
    )
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: fake_tool)

    agent = _agent()
    res = agent.run(str(FIXTURE))
    assert res["mode"] == "local"
    assert res["highest_severity"] == "Critical"
    assert res["findings"][0]["check"] == "reentrancy-eth"


# ── live slither run (skipped if binary absent) ───────────────────────


@requires_slither
def test_live_slither_finds_reentrancy():
    """Real slither against the fixture must flag reentrancy as Critical."""
    tool = SlitherTool()
    findings = tool.analyze(str(FIXTURE))
    checks = [f.check for f in findings]
    assert any("reentrancy" in c for c in checks), f"no reentrancy in {checks}"
    assert highest_tier(findings) == "Critical"


@requires_slither
def test_live_agent_run():
    """Full agent.run against the fixture with the real slither binary."""
    agent = _agent()
    res = agent.run(str(FIXTURE))
    assert res["mode"] == "local"
    assert res["slither_available"] is True
    assert res["highest_severity"] == "Critical"
