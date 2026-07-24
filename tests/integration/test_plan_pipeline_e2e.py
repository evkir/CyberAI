"""End-to-end: the PLAN phase reorders what the exploit phase acts on."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import patch

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase, ScanSession, ScanState

RECON: Dict[str, Any] = {
    "target": "acme.tld",
    "ports": [
        {"port": 22, "service": "ssh", "version": "8.9"},
        {"port": 445, "service": "smb", "version": "4.1"},
    ],
    "subdomains": [],
}

# Deliberately stored in a non-priority order so the planner has to reorder.
CVES: List[Dict[str, Any]] = [
    {"cve_id": "CVE-A", "composite_score": 1.0, "cvss": 3.1, "severity": "LOW", "service": "ssh"},
    {
        "cve_id": "CVE-B",
        "composite_score": 9.0,
        "cvss": 9.8,
        "severity": "CRITICAL",
        "service": "smb",
    },
    {
        "cve_id": "CVE-C",
        "composite_score": 5.0,
        "cvss": 6.5,
        "severity": "MEDIUM",
        "service": "ssh",
    },
]

PLANNED = ["CVE-B", "CVE-C", "CVE-A"]
STORED = ["CVE-A", "CVE-B", "CVE-C"]


def _seed_recon(self: Orchestrator, session: ScanSession) -> Dict[str, Any]:
    session.kb.set("recon.result", RECON)
    session.kb_set("recon", RECON)
    return RECON


def _seed_intel(self: Orchestrator, session: ScanSession) -> Dict[str, Any]:
    session.kb.set("intel.ranked_cves", CVES)
    result = {"ranked_cves": CVES}
    session.kb_set("intel", result)
    return result


def _run(planner: bool) -> tuple[ScanSession, List[str]]:
    cfg = CyberAIConfig()
    cfg.enable_planner = planner
    orch = Orchestrator(
        cfg,
        phases=[ScanPhase.RECON, ScanPhase.INTEL, ScanPhase.EXPLOIT],
        dry_run=False,
    )
    seen: List[str] = []
    original = ExploitAgent._apply_plan_order

    def spy(agent: ExploitAgent, cves: List[Dict]) -> List[Dict]:
        out = original(agent, cves)
        seen.extend(c["cve_id"] for c in out)
        return out

    with (
        patch.object(Orchestrator, "llm", None),
        patch.object(Orchestrator, "_run_recon", _seed_recon),
        patch.object(Orchestrator, "_run_intel", _seed_intel),
        patch.object(ExploitAgent, "_apply_plan_order", spy),
    ):
        session = orch.run("acme.tld", authorized_scope=["acme.tld"])
    return session, seen


def test_plan_phase_reorders_exploit_input():
    session, seen = _run(planner=True)
    assert session.state == ScanState.COMPLETED
    assert [p.phase for p in session.phases] == [
        ScanPhase.RECON,
        ScanPhase.INTEL,
        ScanPhase.PLAN,
        ScanPhase.EXPLOIT,
    ]
    plan = session.kb.get("plan")
    assert [t["target"] for t in plan["todo"] if t["action"] == "exploit"] == PLANNED
    assert seen == PLANNED


def test_plan_graph_carries_services_and_paths():
    session, _ = _run(planner=True)
    graph = session.kb.get("plan")["graph"]
    assert any(n.get("name") == "ssh" for n in graph["nodes"])
    exploit_tasks = [t for t in session.kb.get("plan")["todo"] if t["action"] == "exploit"]
    assert all(t["path"][0] == "acme.tld" for t in exploit_tasks)


def test_pipeline_unchanged_without_planner():
    session, seen = _run(planner=False)
    assert session.state == ScanState.COMPLETED
    assert ScanPhase.PLAN not in [p.phase for p in session.phases]
    assert session.kb.get("plan") is None
    assert seen == STORED
