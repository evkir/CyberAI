"""End-to-end: a synthesized Foundry PoC confirms an on-chain exploit.

forge and Foundry are not installed in CI, so the fork run is represented by a
captured `forge test --json` fixture (verified forge 1.7.x schema). The test
exercises the full path: finding -> synthesized exploit scaffold -> confirmed
PoC -> Critical severity.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.foundry_poc import parse_forge_test_json
from cyberai.agents.web3.poc_synth import ExploitSynthesizer
from cyberai.core.scan_session import ScanSession

FIXTURE = Path(__file__).parent.parent / "fixtures" / "foundry_poc_report.json"

_REENTRANCY_FINDING = {"check": "reentrancy-eth", "target_fn": "withdraw"}


def _agent() -> SmartContractAgent:
    a = SmartContractAgent.__new__(SmartContractAgent)
    a.AGENT_NAME = "web3"
    a._log = MagicMock()
    a.kb = MagicMock()
    a.session = ScanSession(target="x")
    return a


def test_fixture_parses_to_single_confirmed_poc():
    findings = parse_forge_test_json(FIXTURE.read_text())
    # Two suites define testExploit(); only the Success one is confirmed.
    assert len(findings) == 1
    f = findings[0]
    assert f.confirmed is True
    assert f.contract == "test/Exploit.t.sol:ExploitTest"
    assert f.profit_wei == 4000000000000000000


def test_synthesizer_builds_exploit_from_finding():
    script = ExploitSynthesizer().synthesize(_REENTRANCY_FINDING, "Vault")
    assert "contract VaultExploit is Test" in script
    assert "function testExploit() public" in script
    assert "withdraw" in script
    assert 'emit log_named_uint("profit_wei", profit);' in script


def test_agent_surfaces_confirmed_poc_and_severity(tmp_path, monkeypatch):
    # Static analyzers silent; forge returns the fixture confirmed exploit.
    empty = MagicMock()
    empty.available = False
    empty.analyze.return_value = []
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: empty)

    forge = MagicMock()
    forge.available = True
    forge.run.return_value = parse_forge_test_json(FIXTURE.read_text())
    monkeypatch.setattr(ag, "ForgePoCTool", lambda *a, **k: forge)

    sol = tmp_path / "Vault.sol"
    sol.write_text("contract Vault {}")
    res = _agent().run(
        str(sol),
        context={"foundry_project": str(tmp_path), "fork_rpc": "http://127.0.0.1:8545"},
    )

    assert res["poc_available"] is True
    assert len(res["poc_findings"]) == 1
    finding = res["poc_findings"][0]
    assert finding["source"] == "foundry"
    assert finding["confirmed"] is True
    # A confirmed on-chain exploit drives severity to Critical.
    assert res["highest_severity"] == "Critical"


def test_failing_exploit_is_not_confirmed():
    # A report whose exploit test failed yields no finding: no profit, no PoC.
    report = (
        '{"test/X.t.sol:X": {"test_results": {'
        '"testExploit()": {"status": "Failure", "reason": "revert", "decoded_logs": []}}}}'
    )
    assert parse_forge_test_json(report) == []
