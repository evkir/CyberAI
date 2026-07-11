"""End-to-end: an unprotected setOwner is caught and drives a Critical verdict.

The heuristic access-control analyzer is offline, so this runs the full agent
path on a real .sol fixture with the external analyzers muted — proving the
source analyzer alone surfaces a takeover and its escalation path.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import cyberai.agents.web3.agent as ag
from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.core.scan_session import ScanSession

FIXTURE = Path(__file__).parent.parent / "fixtures" / "access_control.sol"


def _agent() -> SmartContractAgent:
    a = SmartContractAgent.__new__(SmartContractAgent)
    a.AGENT_NAME = "web3"
    a._log = MagicMock()
    a.kb = MagicMock()
    a.session = ScanSession(target="x")
    a.tools = {}
    a._register_tools()
    return a


def _mute_external(monkeypatch):
    empty = MagicMock()
    empty.available = False
    empty.analyze.return_value = []
    empty.run.return_value = []
    for name in ("SlitherTool", "AderynTool", "HalmosTool", "ForgePoCTool"):
        monkeypatch.setattr(ag, name, lambda *a, **k: empty)


def test_unprotected_setowner_is_caught_end_to_end(monkeypatch):
    _mute_external(monkeypatch)
    res = _agent().run(str(FIXTURE))

    takeover = [
        f
        for f in res["access_findings"]
        if f["check"] == "missing-auth" and f["function"] == "setOwner"
    ]
    assert takeover, "unprotected setOwner not caught"
    assert res["highest_severity"] == "Critical"

    path = next(p for p in res["escalation_paths"] if p["entry"] == "setOwner")
    assert path["grants"] == "ownership"
    assert "withdrawAll" in path["unlocks"]


def test_guarded_variants_do_not_inflate(monkeypatch):
    _mute_external(monkeypatch)
    res = _agent().run(str(FIXTURE))
    flagged = {f["function"] for f in res["access_findings"]}
    assert "withdrawAll" not in flagged
    assert "setFeeGuarded" not in flagged
    assert "getOwner" not in flagged
