"""Tests for the KB graph, planner, critic, and orchestrator re-plan hook."""

from __future__ import annotations

from unittest.mock import patch

import networkx as nx

from cyberai.agents.planner.agent import PlannerAgent
from cyberai.agents.planner.critic import CriticAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.kb_graph import (
    CVE,
    HOST,
    LLM_ENDPOINT,
    SERVICE,
    attack_paths,
    build_kb_graph,
    nodes_by_type,
    to_dict,
)
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase, ScanSession, ScanState


def _session(target: str = "acme.tld") -> ScanSession:
    return ScanSession(target=target)


# ── kb_graph ──────────────────────────────────────────────────────────


def test_build_graph_full():
    s = _session()
    s.kb.set(
        "recon.result",
        {
            "target": "acme.tld",
            "ports": [
                {"port": 22, "service": "ssh", "version": "8.9"},
                {"port": 443, "service": "https"},
            ],
            "subdomains": ["api.acme.tld"],
        },
    )
    s.kb.set(
        "recon.llm_endpoints",
        {"is_llm_target": True, "llm_endpoints": [{"url": "https://acme.tld/chat"}]},
    )
    s.kb.set(
        "intel.ranked_cves",
        [
            {
                "cve_id": "CVE-2024-9",
                "composite_score": 9.5,
                "severity": "CRITICAL",
                "service": "ssh",
            }
        ],
    )
    g = build_kb_graph(s.kb)

    assert nodes_by_type(g, HOST) == [(HOST, "acme.tld"), (HOST, "api.acme.tld")]
    assert (SERVICE, "ssh") in g
    assert (LLM_ENDPOINT, "https://acme.tld/chat") in g
    paths = attack_paths(g, (HOST, "acme.tld"), (CVE, "CVE-2024-9"))
    assert paths and paths[0][-1] == (CVE, "CVE-2024-9")


def test_empty_target_returns_empty_graph():
    assert build_kb_graph(_session().kb).number_of_nodes() == 0


def test_non_dict_recon_result():
    s = _session()
    s.kb.set("recon.result", "garbage")
    g = build_kb_graph(s.kb, target="acme.tld")
    assert g.number_of_nodes() == 1  # root host only


def test_intel_result_fallback_and_link_variants():
    s = _session()
    s.kb.set("recon.result", {"target": "acme.tld", "ports": [{"port": 22, "service": "ssh"}]})
    s.kb.set(
        "intel.result",
        {
            "cves": [
                {"id": "CVE-A", "cvss": 7.0, "severity": "HIGH", "service": "ssh"},
                {"id": "CVE-B", "cvss": 5.0, "severity": "MEDIUM"},
                {"noid": 1},  # missing id -> skipped
                "not-a-dict",  # non-dict -> skipped
            ]
        },
    )
    g = build_kb_graph(s.kb)
    # service-matched CVE hangs off the service node; unmatched hangs off root.
    assert g.has_edge((SERVICE, "ssh"), (CVE, "CVE-A"))
    assert g.has_edge((HOST, "acme.tld"), (CVE, "CVE-B"))


def test_build_graph_skips_malformed_entries():
    s = _session()
    s.kb.set(
        "recon.result",
        {
            "target": "acme.tld",
            "ports": [
                {"port": 22, "service": "ssh"},
                {"no": "port"},
                "not-a-dict",
                {"port": 80, "service": "unknown"},
            ],
            "subdomains": ["sub.acme.tld", ""],
        },
    )
    s.kb.set(
        "recon.llm_endpoints",
        {"is_llm_target": True, "llm_endpoints": [{"url": "u"}, {"nourl": 1}, "bad"]},
    )
    s.kb.set(
        "intel.ranked_cves",
        [{"cve_id": "C1", "service": "ssh"}, {"nocve": 1}, "bad"],
    )
    g = build_kb_graph(s.kb)
    assert (SERVICE, "ssh") in g
    assert (SERVICE, "unknown") not in g  # "unknown" service is not a node
    assert nodes_by_type(g, LLM_ENDPOINT) == [(LLM_ENDPOINT, "u")]
    assert nodes_by_type(g, CVE) == [(CVE, "C1")]


def test_attack_paths_missing_node():
    g = nx.DiGraph()
    g.add_node((HOST, "a"), ntype=HOST, name="a")
    assert attack_paths(g, (HOST, "nope"), (CVE, "x")) == []


def test_to_dict_shape():
    s = _session()
    s.kb.set("recon.result", {"target": "acme.tld", "ports": [{"port": 22, "service": "ssh"}]})
    d = to_dict(build_kb_graph(s.kb))
    assert {"type", "name"} <= set(d["nodes"][0])
    assert {"from", "to", "rel"} <= set(d["edges"][0])


# ── PlannerAgent ──────────────────────────────────────────────────────


def test_planner_orders_by_score_and_stores_plan():
    s = _session()
    s.kb.set(
        "recon.result",
        {
            "target": "acme.tld",
            "ports": [{"port": 22, "service": "ssh"}, {"port": 443, "service": "https"}],
        },
    )
    s.kb.set(
        "recon.llm_endpoints",
        {"is_llm_target": True, "llm_endpoints": [{"url": "https://acme.tld/chat"}]},
    )
    s.kb.set(
        "intel.ranked_cves",
        [
            {"cve_id": "CVE-LOW", "composite_score": 4.0, "service": "ssh"},
            {"cve_id": "CVE-HIGH", "composite_score": 9.5, "service": "https"},
            {"cve_id": "CVE-NOSCORE", "service": "ssh"},  # score None -> _score except
        ],
    )
    r = PlannerAgent(CyberAIConfig(), s).run("acme.tld")
    actions = [t["action"] for t in r["todo"]]
    assert actions.count("exploit") == 3
    assert "injection-fuzz" in actions
    assert "enumerate" in actions
    # Highest score first.
    exploit_targets = [t["target"] for t in r["todo"] if t["action"] == "exploit"]
    assert exploit_targets[0] == "CVE-HIGH"
    assert s.kb.get("plan")["target"] == "acme.tld"
    assert all("id" in t for t in r["todo"])


def test_planner_empty_kb():
    assert PlannerAgent(CyberAIConfig(), _session("x")).run("x")["subtasks"] == 0


def test_plan_fallback_path_when_cve_unreachable():
    g = nx.DiGraph()
    g.add_node((HOST, "t"), ntype=HOST, name="t")
    g.add_node((CVE, "CVE-X"), ntype=CVE, name="CVE-X", score=5, severity="HIGH")
    agent = PlannerAgent(CyberAIConfig(), _session("t"))
    todo = agent._plan_from_graph(g, "t")
    assert todo[0]["path"] == ["t", "CVE-X"]


# ── CriticAgent ───────────────────────────────────────────────────────


def test_critic_retry_on_transient():
    s = _session()
    v = CriticAgent(CyberAIConfig(), s).run(
        "t", context={"phase": "recon", "error": "Connection timeout"}
    )
    assert v["decision"] == "retry"
    assert s.kb.get("critic.recon")["decision"] == "retry"


def test_critic_skip_on_permanent_and_default_context():
    v = CriticAgent(CyberAIConfig(), _session()).run("t")  # context=None -> unknown/skip
    assert v == {
        "phase": "unknown",
        "decision": "skip",
        "reason": "non-transient failure — skipping",
    }


# ── orchestrator re-plan hook ─────────────────────────────────────────


def _orch(enable: bool) -> Orchestrator:
    cfg = CyberAIConfig()
    cfg.enable_replan = enable
    return Orchestrator(cfg, phases=[ScanPhase.RECON], dry_run=False)


def test_replan_retry_success_collapses_to_completed():
    orch = _orch(True)
    with patch.object(
        orch, "_dispatch", side_effect=[Exception("Connection timeout"), {"ok": True}]
    ):
        s = orch.run("10.0.0.1")
    assert s.state == ScanState.COMPLETED
    assert len(s.phases) == 1 and s.phases[-1].success


def test_replan_retry_fails_again_no_pop():
    orch = _orch(True)
    with patch.object(orch, "_dispatch", side_effect=[Exception("timeout"), Exception("timeout")]):
        s = orch.run("10.0.0.1")
    assert s.state == ScanState.FAILED
    assert len(s.phases) == 2


def test_replan_skip_on_permanent():
    orch = _orch(True)
    with patch.object(orch, "_dispatch", side_effect=Exception("Scope check failed")):
        s = orch.run("10.0.0.1")
    assert s.state == ScanState.FAILED
    assert len(s.phases) == 1


def test_replan_disabled_no_retry():
    orch = _orch(False)
    with patch.object(orch, "_dispatch", side_effect=Exception("timeout")) as md:
        s = orch.run("10.0.0.1")
    assert s.state == ScanState.FAILED
    assert md.call_count == 1  # no retry when flag off


def test_maybe_replan_guard_already_retried():
    orch = _orch(True)
    s = _session()
    # Simulate a phase that already appears twice — guard must early-return.
    orch._run_phase = lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run"))
    s.set_phase(ScanPhase.RECON)
    s.record_phase(ScanPhase.RECON, success=False, started="t0", error="timeout")
    s.record_phase(ScanPhase.RECON, success=False, started="t1", error="timeout")
    orch._maybe_replan(s, ScanPhase.RECON)  # attempts == 2 -> returns without _run_phase
    assert s.kb.get("critic.recon") is None
