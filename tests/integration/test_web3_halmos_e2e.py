"""End-to-end: a halmos counterexample on a reentrant vault becomes a finding.

halmos and Foundry are not installed in CI, so the symbolic run is represented
by a captured `--json-output` fixture (verified halmos 0.3.x schema). The test
exercises the full path: ABI -> synthesized harness -> counterexample -> finding.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.halmos_tool import parse_halmos_json
from cyberai.agents.web3.property_synth import render_harness, synthesize_properties
from cyberai.core.scan_session import ScanSession

FIXTURE = Path(__file__).parent.parent / "fixtures" / "halmos_report.json"

# Minimal TheDAO-style ABI: a payable deposit and a reentrant withdraw.
_DAO_ABI = [
    {"type": "function", "name": "deposit", "inputs": [], "stateMutability": "payable"},
    {"type": "function", "name": "withdraw", "inputs": [], "stateMutability": "nonpayable"},
]


def _agent() -> SmartContractAgent:
    a = SmartContractAgent.__new__(SmartContractAgent)
    a.AGENT_NAME = "web3"
    a._log = MagicMock()
    a.kb = MagicMock()
    a.session = ScanSession(target="x")
    return a


def test_fixture_parses_to_single_counterexample():
    findings = parse_halmos_json(FIXTURE.read_text())
    # The reentrancy check breaks (exitcode 1); the overflow check passed.
    assert len(findings) == 1
    f = findings[0]
    assert f.test_name == "check_reentrancy_withdraw(address)"
    assert f.contract == "test/DaoReentrant.t.sol:DaoReentrantSymTest"
    assert f.num_models == 1
    assert f.models == [{"path_id": 7, "result": "sat"}]


def test_synthesizer_targets_reentrant_functions():
    cands = synthesize_properties(_DAO_ABI, "DaoReentrant")
    kinds = {c.target_fn: c.kind for c in cands}
    assert kinds["withdraw"] == "reentrancy"
    assert kinds["deposit"] == "reentrancy"  # payable
    harness = render_harness("DaoReentrant", cands)
    assert "check_reentrancy_withdraw" in harness
    assert "contract DaoReentrantSymTest is SymTest, Test {" in harness


def test_agent_surfaces_counterexample_as_finding(tmp_path, monkeypatch):
    # Static analyzers silent; halmos returns the fixture counterexample.
    empty = MagicMock()
    empty.available = False
    empty.analyze.return_value = []
    monkeypatch.setattr(ag, "SlitherTool", lambda *a, **k: empty)
    monkeypatch.setattr(ag, "AderynTool", lambda *a, **k: empty)

    halmos = MagicMock()
    halmos.available = True
    halmos.analyze.return_value = parse_halmos_json(FIXTURE.read_text())
    monkeypatch.setattr(ag, "HalmosTool", lambda *a, **k: halmos)

    sol = tmp_path / "DaoReentrant.sol"
    sol.write_text("contract DaoReentrant {}")
    res = _agent().run(str(sol), context={"halmos_project": str(tmp_path)})

    assert res["halmos_available"] is True
    assert len(res["halmos_findings"]) == 1
    finding = res["halmos_findings"][0]
    assert finding["test"] == "check_reentrancy_withdraw(address)"
    assert finding["source"] == "halmos"
    # A proven invariant break drives severity when static tools stay silent.
    assert res["highest_severity"] == "High"
