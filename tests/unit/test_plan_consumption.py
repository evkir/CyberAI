"""ExploitAgent honours the planner TODO ordering."""

from __future__ import annotations

from typing import Any, Dict, List

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


def _agent(plan: Any = None) -> ExploitAgent:
    session = ScanSession(target="acme.tld")
    if plan is not None:
        session.kb_set("plan", plan)
    return ExploitAgent(CyberAIConfig(), session)


def _cves() -> List[Dict]:
    return [{"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}, {"cve_id": "CVE-3"}]


def _ids(cves: List[Dict]) -> List[str]:
    return [c["cve_id"] for c in cves]


BASE = ["CVE-1", "CVE-2", "CVE-3"]


def test_no_plan_keeps_order():
    assert _ids(_agent()._apply_plan_order(_cves())) == BASE


def test_plan_reorders_cves():
    plan = {
        "todo": [
            {"action": "exploit", "target": "CVE-3"},
            {"action": "exploit", "target": "CVE-1"},
        ]
    }
    assert _ids(_agent(plan)._apply_plan_order(_cves())) == ["CVE-3", "CVE-1", "CVE-2"]


def test_plan_ignores_non_exploit_and_malformed_entries():
    plan = {
        "todo": [
            None,
            {"action": "enumerate", "target": "ssh"},
            {"action": "exploit", "target": None},
            {"action": "exploit", "target": "CVE-2"},
        ]
    }
    assert _ids(_agent(plan)._apply_plan_order(_cves())) == ["CVE-2", "CVE-1", "CVE-3"]


def test_plan_without_exploit_actions_keeps_order():
    plan = {"todo": [{"action": "enumerate", "target": "ssh"}]}
    assert _ids(_agent(plan)._apply_plan_order(_cves())) == BASE


def test_plan_with_unknown_cves_keeps_order():
    plan = {"todo": [{"action": "exploit", "target": "CVE-9999"}]}
    assert _ids(_agent(plan)._apply_plan_order(_cves())) == BASE


def test_malformed_plan_keeps_order():
    assert _ids(_agent("not-a-dict")._apply_plan_order(_cves())) == BASE
    assert _ids(_agent({"todo": []})._apply_plan_order(_cves())) == BASE
    assert _ids(_agent({"todo": "nope"})._apply_plan_order(_cves())) == BASE
