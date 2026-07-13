"""LLM-judge validation for Web3 findings.

The judge is reused from the report layer, so these tests focus on the Web3
adapter: raw detector findings become evidence, the shared judge is invoked,
and the graceful-degradation contract is preserved.
"""

from unittest.mock import MagicMock

from cyberai.agents.web3.judge import _evidence_session, judge_web3_findings
from cyberai.core.scan_session import Severity


def _agent_result() -> dict:
    return {
        "target": "contracts/Vault.sol",
        "poc_findings": [
            {
                "check": "onchain-poc-exploit",
                "contract": "Vault",
                "function": "withdraw",
                "description": "Reentrancy drains the vault on a mainnet fork.",
                "profit_wei": 5000000000000000000,
            }
        ],
        "findings": [
            {
                "check": "reentrancy-eth",
                "contract": "Vault",
                "description": "External call before state update.",
                "impact": "High",
                "confidence": "High",
            }
        ],
    }


def _llm_returning(payload: dict) -> MagicMock:
    llm = MagicMock()
    llm.config = MagicMock()
    llm.config.model = "gpt-4o"
    llm.structured_call.return_value = payload
    return llm


def test_evidence_session_maps_findings():
    """Both buckets become evidence findings with tier-mapped severity."""
    session = _evidence_session(_agent_result())
    assert session.target == "contracts/Vault.sol"
    assert len(session.findings) == 2
    titles = {f.title for f in session.findings}
    assert "onchain-poc-exploit in Vault.withdraw" in titles
    poc = [f for f in session.findings if "onchain" in f.title][0]
    assert poc.severity == Severity.CRITICAL
    assert any("profit_wei=" in str(e) for e in poc.evidence)


def test_evidence_session_skips_non_dict():
    result = {"target": "x", "findings": ["not-a-dict", None]}
    session = _evidence_session(result)
    assert session.findings == []


def test_evidence_session_default_target():
    session = _evidence_session({"findings": []})
    assert session.target == "web3-audit"


def test_judge_catches_unsupported_claim():
    """Draft asserts a vuln class absent from evidence → judge flags it."""
    llm = _llm_returning(
        {
            "hallucination_score": 0.9,
            "supported": False,
            "unsupported_claims": ["Claims an access-control bug not in evidence"],
            "notes": "fabricated finding",
        }
    )
    verdict = judge_web3_findings("draft with a made-up bug", _agent_result(), llm)
    assert verdict.supported is False
    assert verdict.hallucination_score == 0.9
    assert verdict.unsupported_claims


def test_judge_passes_grounded_draft():
    llm = _llm_returning(
        {
            "hallucination_score": 0.0,
            "supported": True,
            "unsupported_claims": [],
            "notes": "all claims backed",
        }
    )
    verdict = judge_web3_findings("grounded draft", _agent_result(), llm)
    assert verdict.supported is True


def test_judge_graceful_without_llm():
    verdict = judge_web3_findings("draft", _agent_result(), None)
    assert verdict.supported is True
    assert "unavailable" in verdict.notes
