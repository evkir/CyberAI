"""The planner turns discovered HTTP endpoints into web-exploit subtasks."""

from __future__ import annotations

from typing import Any, Dict, List

from cyberai.agents.planner.agent import PlannerAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession

TARGET = "acme.tld"
BASE = "http://acme.tld"

SURFACE = {
    "endpoints": [
        {
            "url": f"{BASE}/switch_personal_path",
            "method": "GET",
            "params": ["path"],
            "body_params": ["path"],
            "source": "openapi",
        },
        {"url": f"{BASE}/search", "method": "POST", "params": ["q", "page"]},
    ],
    "routes": [{"url": f"{BASE}/done", "method": "GET", "params": []}],
}


def _todo(surface: Any = None, ranked_cves: Any = None) -> List[Dict[str, Any]]:
    s = ScanSession(target=TARGET)
    s.kb.set("recon.result", {"target": TARGET})
    if surface is not None:
        s.kb.set("recon.web_surface", surface)
    if ranked_cves is not None:
        s.kb.set("intel.ranked_cves", ranked_cves)
    return PlannerAgent(CyberAIConfig(), s).run(TARGET)["todo"]


def _web(todo: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [t for t in todo if t["action"] == "web-exploit"]


def test_endpoints_become_web_exploit_subtasks():
    tasks = _web(_todo(SURFACE))
    assert [t["target"] for t in tasks] == [
        f"{BASE}/switch_personal_path",
        f"{BASE}/search",
    ]
    first = tasks[0]
    assert first["method"] == "GET"
    assert first["params"] == ["path"]
    assert first["body_params"] == ["path"]
    assert first["path"] == [TARGET, f"{BASE}/switch_personal_path"]
    assert tasks[1]["body_params"] == []


def test_parameterless_routes_produce_no_subtask():
    assert all(t["target"] != f"{BASE}/done" for t in _web(_todo(SURFACE)))


def test_subtasks_are_numbered_with_the_rest_of_the_plan():
    todo = _todo(SURFACE, ranked_cves=[{"cve_id": "CVE-2024-9", "composite_score": 9.5}])
    assert [t["id"] for t in todo] == list(range(1, len(todo) + 1))
    assert todo[0]["action"] == "exploit"
    assert [t["action"] for t in todo[1:3]] == ["web-exploit", "web-exploit"]


def test_no_web_surface_yields_no_web_subtasks():
    assert _web(_todo()) == []
    assert _web(_todo({"endpoints": []})) == []


# ── LLM channels carry their contract into the plan ───────────────────


def _fuzz(todo: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [t for t in todo if t["action"] == "injection-fuzz"]


def test_a_chat_route_becomes_a_fuzz_subtask_with_its_field():
    """The field name has to survive graph-to-plan, not merely exist on the node.

    Without it the red team falls back to guessing five field names, none of
    which the target reads, and the run reports a delivered payload that
    carried nothing.
    """
    todo = _todo(
        {
            "endpoints": [
                {"url": f"{BASE}/rest/chat", "method": "POST", "params": ["messages"]},
                {"url": f"{BASE}/search", "method": "POST", "params": ["q", "page"]},
            ]
        }
    )

    tasks = _fuzz(todo)
    assert [t["target"] for t in tasks] == [f"{BASE}/rest/chat"]
    assert tasks[0]["prompt_field"] == "messages"
    assert tasks[0]["method"] == "POST"


def test_a_detector_channel_keeps_the_key_with_no_field():
    """Control: a node the path detector found has no contract to carry.

    The key is present and null rather than absent, so a consumer reads an
    answer instead of a KeyError.
    """
    s = ScanSession(target=TARGET)
    s.kb.set("recon.result", {"target": TARGET})
    s.kb.set(
        "recon.llm_endpoints",
        {"is_llm_target": True, "llm_endpoints": [{"url": f"{BASE}/v1/chat/completions"}]},
    )

    tasks = _fuzz(PlannerAgent(CyberAIConfig(), s).run(TARGET)["todo"])

    assert [t["target"] for t in tasks] == [f"{BASE}/v1/chat/completions"]
    assert tasks[0]["prompt_field"] is None
