"""The red-team agent drives planned LLM channels and records what holds."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

from cyberai.agents.redteam.agent import RedTeamAgent, _default_channel
from cyberai.agents.redteam.fuzzer import FuzzReport, FuzzResult
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession, Severity

CHAT = "http://t.local/chat"
RAG = "http://t.local/v1/completions"

PLAN = {
    "todo": [
        {"action": "exploit", "target": "CVE-1"},
        {"action": "injection-fuzz", "target": CHAT},
        {"action": "injection-fuzz", "target": RAG},
    ]
}


class _StubFuzzer:
    """Stand-in fuzzer: records channels and replays canned results."""

    def __init__(self, results: List[FuzzResult] | None = None):
        self.channels: List[str] = []
        self.sent: List[str] = []
        self._results = results or []

    def fuzz_channel(self, send_fn, channel_id: str = "") -> FuzzReport:
        self.channels.append(channel_id)
        self.sent.append(send_fn("payload-probe"))
        return FuzzReport(channel_id=channel_id, results=list(self._results))


def _agent(plan: Any = None) -> RedTeamAgent:
    session = ScanSession(target="t.local")
    if plan is not None:
        session.kb_set("plan", plan)
    return RedTeamAgent(CyberAIConfig(), session, MagicMock(), MagicMock())


def _run(agent: RedTeamAgent, fuzzer: Any, **ctx: Any) -> Dict[str, Any]:
    return agent.run("t.local", {"fuzzer": fuzzer, "channel_factory": lambda u: lambda p: u, **ctx})


def test_channels_follow_plan_order():
    agent = _agent(PLAN)
    fuzzer = _StubFuzzer()
    result = _run(agent, fuzzer)
    assert fuzzer.channels == [CHAT, RAG]
    assert result["channels"] == 2


def test_duplicate_targets_are_fuzzed_once():
    plan = {"todo": [{"action": "injection-fuzz", "target": CHAT}] * 3}
    fuzzer = _StubFuzzer()
    _run(_agent(plan), fuzzer)
    assert fuzzer.channels == [CHAT]


def test_no_plan_or_no_fuzz_subtasks_does_nothing():
    for plan in (None, "not-a-dict", {"todo": []}, {"todo": [{"action": "exploit"}]}):
        fuzzer = _StubFuzzer()
        result = _run(_agent(plan), fuzzer)
        assert fuzzer.channels == []
        assert result == {"channels": 0, "confirmed": 0, "reports": []}


def test_confirmed_result_becomes_a_finding_with_full_confidence():
    agent = _agent(PLAN)
    oob = FuzzResult(
        payload_id="p1",
        category="exfiltration",
        oob_confirmed=True,
        severity="CRITICAL",
        detail="out-of-band callback confirmed",
    )
    result = _run(agent, _StubFuzzer([oob]))

    assert result["confirmed"] == 2  # one per channel
    findings = agent.session.findings
    assert len(findings) == 2
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].target == CHAT
    assert findings[0].confidence == 1.0


def test_unconfirmed_signal_is_recorded_below_full_confidence():
    agent = _agent({"todo": [{"action": "injection-fuzz", "target": CHAT}]})
    echoed = FuzzResult(payload_id="p2", category="jailbreak", ack_echoed=True, severity="HIGH")
    _run(agent, _StubFuzzer([echoed]))

    finding = agent.session.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.confidence < 1.0


def test_info_results_produce_no_finding():
    agent = _agent({"todo": [{"action": "injection-fuzz", "target": CHAT}]})
    quiet = FuzzResult(payload_id="p3", category="jailbreak", severity="INFO")
    _run(agent, _StubFuzzer([quiet]))
    assert agent.session.findings == []


def test_reports_are_stored_in_the_knowledge_base():
    agent = _agent(PLAN)
    _run(agent, _StubFuzzer())
    stored = agent.session.kb.get("redteam.reports")
    assert [r["channel_id"] for r in stored] == [CHAT, RAG]


def test_default_channel_posts_the_payload_under_known_field_names():
    sent: Dict[str, Any] = {}

    class _Resp:
        text = "answer"

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json):
            sent["url"] = url
            sent["json"] = json
            return _Resp()

    import cyberai.agents.redteam.agent as mod

    original = mod.httpx.Client
    mod.httpx.Client = lambda **kw: _Client()
    try:
        assert _default_channel(CHAT)("INJECT") == "answer"
    finally:
        mod.httpx.Client = original

    assert sent["url"] == CHAT
    assert set(sent["json"].values()) == {"INJECT"}
    assert "prompt" in sent["json"]


def test_default_channel_survives_a_dead_target():
    import cyberai.agents.redteam.agent as mod

    original = mod.httpx.Client

    def _boom(**kw):
        raise RuntimeError("connection refused")

    mod.httpx.Client = _boom
    try:
        assert _default_channel(CHAT)("INJECT") == ""
    finally:
        mod.httpx.Client = original


# ── orchestrator wiring ───────────────────────────────────────────────


def test_orchestrator_skips_red_team_without_the_flag():
    from cyberai.core.orchestrator import Orchestrator

    orch = Orchestrator(CyberAIConfig())
    session = ScanSession(target="t.local")
    session.kb_set("plan", PLAN)
    assert orch._run_planned_redteam(session) == {}


def test_orchestrator_runs_red_team_when_enabled():
    from unittest.mock import patch

    from cyberai.core.orchestrator import Orchestrator

    orch = Orchestrator(CyberAIConfig(use_planned_redteam=True))
    orch.audit = MagicMock()
    session = ScanSession(target="t.local")
    session.kb_set("plan", PLAN)

    with (
        patch.object(Orchestrator, "_client_for", return_value=MagicMock()),
        patch("cyberai.agents.redteam.agent.LLMChannelFuzzer", return_value=_StubFuzzer()),
        # Without this the stub calls the real channel, which spends a full
        # connect timeout per host proving nothing about the wiring.
        patch("cyberai.agents.redteam.agent._default_channel", lambda url: lambda p: ""),
    ):
        result = orch._run_planned_redteam(session)

    assert result["channels"] == 2
