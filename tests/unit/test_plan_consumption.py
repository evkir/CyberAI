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


# ── web-exploit ordering ──────────────────────────────────────────────


def _web_agent(plan: Any = None, flag: bool = True) -> ExploitAgent:
    session = ScanSession(target="acme.tld")
    if plan is not None:
        session.kb_set("plan", plan)
    return ExploitAgent(CyberAIConfig(use_plan_web_order=flag), session)


WEB_PLAN = {
    "todo": [
        {"action": "exploit", "target": "CVE-1"},
        {"action": "web-exploit", "target": "http://acme.tld/b", "method": "post"},
        {"action": "web-exploit", "target": "http://acme.tld/a"},
    ]
}


def test_web_priority_follows_plan_order():
    assert _web_agent(WEB_PLAN)._plan_web_priority() == [
        ("http://acme.tld/b", "POST"),
        ("http://acme.tld/a", "GET"),
    ]


def test_web_priority_off_by_default():
    assert (
        ExploitAgent(CyberAIConfig(), ScanSession(target="acme.tld"))._plan_web_priority() is None
    )
    assert _web_agent(WEB_PLAN, flag=False)._plan_web_priority() is None


def test_web_priority_none_without_usable_plan():
    assert _web_agent()._plan_web_priority() is None
    assert _web_agent("not-a-dict")._plan_web_priority() is None
    assert _web_agent({"todo": "nope"})._plan_web_priority() is None
    assert _web_agent({"todo": []})._plan_web_priority() is None
    assert (
        _web_agent({"todo": [{"action": "exploit", "target": "CVE-1"}]})._plan_web_priority()
        is None
    )


def test_web_priority_skips_malformed_entries():
    plan = {
        "todo": [
            None,
            {"action": "web-exploit", "target": None},
            {"action": "web-exploit", "target": "http://acme.tld/a"},
        ]
    }
    assert _web_agent(plan)._plan_web_priority() == [("http://acme.tld/a", "GET")]
