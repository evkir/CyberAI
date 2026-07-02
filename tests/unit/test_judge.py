"""LLM-as-Judge: catches hallucinated claims in reports.

The judge is an LLM call, so we mock `structured_call` and verify the
judge logic: hallucination detection, threshold authority, graceful
degradation, evidence collection, model swap, and score clamping.
"""

from unittest.mock import MagicMock

from cyberai.agents.report.judge import (
    JudgeVerdict,
    _collect_evidence,
    _judge_model,
    judge_report,
)
from cyberai.core.scan_session import ScanSession, Severity


def _session_with_findings() -> ScanSession:
    s = ScanSession(target="testhost.local")
    s.add_finding(
        severity=Severity.INFO,
        title="Open SSH Port",
        description="22/tcp open",
        agent="recon",
    )
    s.add_finding(
        severity=Severity.CRITICAL,
        title="Log4Shell",
        description="JNDI lookup confirmed",
        agent="exploit",
        cve_ids=["CVE-2021-44228"],
    )
    return s


def _llm_returning(payload: dict) -> MagicMock:
    llm = MagicMock()
    llm.config = MagicMock()
    llm.config.model = "gpt-4o"
    llm.structured_call.return_value = payload
    return llm


def test_judge_catches_hallucinated_cve():
    """Report cites CVE-9999-99999 (not in KB) → judge flags it unsupported."""
    s = _session_with_findings()
    llm = _llm_returning(
        {
            "hallucination_score": 0.9,
            "supported": False,
            "unsupported_claims": ["Report cites CVE-9999-99999, absent from evidence"],
            "notes": "fabricated CVE",
        }
    )
    verdict = judge_report("...CVE-9999-99999...", s, llm)
    assert verdict.supported is False
    assert verdict.hallucination_score == 0.9
    assert any("9999" in c for c in verdict.unsupported_claims)


def test_judge_passes_clean_report():
    s = _session_with_findings()
    llm = _llm_returning(
        {
            "hallucination_score": 0.0,
            "supported": True,
            "unsupported_claims": [],
            "notes": "all claims backed",
        }
    )
    verdict = judge_report("clean report", s, llm)
    assert verdict.supported is True
    assert verdict.hallucination_score == 0.0


def test_threshold_is_authoritative():
    """Model lies (supported=True at 0.85) → judge recomputes from threshold."""
    s = _session_with_findings()
    llm = _llm_returning(
        {
            "hallucination_score": 0.85,
            "supported": True,  # model's claim — must be overridden
            "unsupported_claims": ["x"],
            "notes": "",
        }
    )
    verdict = judge_report("report", s, llm, threshold=0.7)
    assert verdict.supported is False  # 0.85 >= 0.7


def test_graceful_on_exception():
    """structured_call raises → graceful pass-through verdict, no crash."""
    s = _session_with_findings()
    llm = MagicMock()
    llm.config = MagicMock()
    llm.config.model = "gpt-4o"
    llm.structured_call.side_effect = RuntimeError("API down")
    verdict = judge_report("report", s, llm)
    assert verdict.supported is True
    assert verdict.hallucination_score == 0.0
    assert "unavailable" in verdict.notes


def test_graceful_on_no_llm():
    s = _session_with_findings()
    verdict = judge_report("report", s, None)
    assert verdict.supported is True
    assert "unavailable" in verdict.notes


def test_collect_evidence_serializes_findings():
    s = _session_with_findings()
    ev = _collect_evidence(s)
    assert ev["target"] == "testhost.local"
    assert len(ev["findings"]) == 2
    log4shell = [f for f in ev["findings"] if f["title"] == "Log4Shell"][0]
    assert log4shell["severity"] == "CRITICAL"
    assert "CVE-2021-44228" in log4shell["cve_ids"]


def test_collect_evidence_truncates_long_evidence():
    s = ScanSession(target="x")
    s.add_finding(
        severity=Severity.HIGH,
        title="Big",
        description="d",
        agent="t",
    )
    s.findings[0].evidence = ["A" * 1000]
    ev = _collect_evidence(s)
    assert len(ev["findings"][0]["evidence"][0]) == 500


def test_judge_model_swap_and_restore():
    """_judge_model temporarily swaps config.model and restores it."""
    llm = MagicMock()
    llm.config = MagicMock()
    llm.config.model = "gpt-4o"
    with _judge_model(llm, "gpt-4o-judge"):
        assert llm.config.model == "gpt-4o-judge"
    assert llm.config.model == "gpt-4o"


def test_judge_model_noop_when_none():
    llm = MagicMock()
    llm.config = MagicMock()
    llm.config.model = "gpt-4o"
    with _judge_model(llm, None):
        assert llm.config.model == "gpt-4o"
    assert llm.config.model == "gpt-4o"


def test_judge_model_used_in_call():
    """judge_model is applied during the structured_call."""
    s = _session_with_findings()
    captured = {}

    def _capture(*args, **kwargs):
        captured["model"] = llm.config.model
        return {
            "hallucination_score": 0.0,
            "supported": True,
            "unsupported_claims": [],
            "notes": "",
        }

    llm = MagicMock()
    llm.config = MagicMock()
    llm.config.model = "gpt-4o"
    llm.structured_call.side_effect = _capture
    judge_report("r", s, llm, judge_model="big-model")
    assert captured["model"] == "big-model"
    assert llm.config.model == "gpt-4o"  # restored


def test_verdict_score_clamped():
    assert JudgeVerdict(hallucination_score=1.5).hallucination_score == 1.0
    assert JudgeVerdict(hallucination_score=-0.3).hallucination_score == 0.0
