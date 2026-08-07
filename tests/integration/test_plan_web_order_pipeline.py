"""The planner's endpoint order survives the whole pipeline.

Each link was proven in isolation: the graph gains HTTP endpoint nodes, the
planner emits web-exploit subtasks, `exploit_surface` accepts a priority, and
the exploit agent reads the plan. None of that proves they meet. A phase
reordering, a KB key rename, or a plan written after the exploit phase reads
it would leave every unit test green and the order silently dropped, which is
exactly the failure this pipeline was built to avoid.
"""

from __future__ import annotations

from typing import Dict, List
from unittest.mock import MagicMock, patch

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanPhase

TARGET = "t.local"
BASE = "http://t.local"
# `dull` carries no hinted parameter name, so the deterministic order would
# put it last; naming it first in the plan is what has to survive.
DULL = f"{BASE}/dull"
HINTED = f"{BASE}/read"

SURFACE = {
    "base_url": BASE,
    "reachable": True,
    "pages_fetched": 1,
    # Order matters: the plan follows graph insertion order, while the
    # deterministic ranking follows the parameter name hint. Listing the dull
    # endpoint first makes the two disagree, so the attack order proves which
    # one actually ran instead of agreeing with both.
    "endpoints": [
        {"url": DULL, "method": "POST", "params": ["zzz"], "source": "hint"},
        {"url": HINTED, "method": "GET", "params": ["path"], "source": "hint"},
    ],
    "routes": [],
    "spec_url": None,
}

RECON_RESULT = {"target": TARGET, "ports": [], "subdomains": []}


def _config(**flags) -> CyberAIConfig:
    return CyberAIConfig(
        enable_planner=True,
        use_web_exploit=True,
        **flags,
    )


def _run(config: CyberAIConfig) -> List[str]:
    """Run recon->plan->exploit with a stand-in sender; return attack order."""
    hit: List[str] = []

    def send(url: str, method: str, params: Dict[str, str]) -> str:
        hit.append(url)
        return ""

    orch = Orchestrator(
        config,
        phases=[ScanPhase.RECON, ScanPhase.EXPLOIT],
    )
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=RECON_RESULT),
        patch("cyberai.agents.recon.agent.run_whois", return_value={}),
        patch("cyberai.agents.recon.agent.run_dns", return_value={}),
        patch("cyberai.agents.recon.agent.enumerate_subdomains", return_value={}),
        patch("cyberai.agents.recon.agent.detect_llm_endpoints", return_value={}),
        patch("cyberai.agents.recon.agent.discover_surface", return_value=SURFACE),
        patch("cyberai.agents.exploit.web_exploit._default_sender", return_value=send),
        patch("cyberai.agents.exploit.web_exploit._default_json_sender", return_value=send),
        patch("cyberai.core.orchestrator.Orchestrator._client_for", return_value=MagicMock()),
    ):
        session = orch.run(TARGET)

    # The phantom check probes paths no surface declares. They are traffic, not
    # attack order, and this test is about the order the plan produced.
    declared = {DULL, HINTED}
    return list(dict.fromkeys(u for u in hit if u in declared)), session


def test_plan_phase_is_inserted_and_writes_web_subtasks():
    _, session = _run(_config(use_web_recon=True, use_plan_web_order=True))
    todo = (session.kb.get("plan") or {}).get("todo") or []
    web = [(t["target"], t["method"]) for t in todo if t["action"] == "web-exploit"]
    assert web == [(DULL, "POST"), (HINTED, "GET")]


def test_plan_order_reaches_the_attack():
    order, _ = _run(_config(use_web_recon=True, use_plan_web_order=True))
    # Against the name hint, which would put HINTED first.
    assert order == [DULL, HINTED]


def test_without_the_flag_the_deterministic_order_runs():
    order, _ = _run(_config(use_web_recon=True))
    assert order == [HINTED, DULL]
