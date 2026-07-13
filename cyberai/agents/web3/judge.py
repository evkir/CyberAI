"""LLM-judge validation for Web3 audit findings.

Reuses the report LLM-judge to cross-check a Web3 audit narrative (for
example an Immunefi submission draft) against the raw detector evidence a
Web3 scan actually produced. Guards against hallucinated vulnerability
classes, CVEs, or impact claims that no tool in the chain (Slither, aderyn,
access-control, halmos, or a Foundry PoC) backs.
"""

from __future__ import annotations

from typing import Any, Optional

from cyberai.agents.report.judge import JudgeVerdict, judge_report
from cyberai.agents.web3.immunefi_report import (
    _FINDING_KEYS,
    _TIER_TO_INTERNAL,
    _finding_title,
    immunefi_tier,
)
from cyberai.core.llm_client import LLMClient
from cyberai.core.scan_session import ScanSession, Severity


def _evidence_session(agent_result: dict[str, Any]) -> ScanSession:
    """Build a ScanSession whose findings are the raw detector evidence.

    Each detector hit (Slither, aderyn, access-control, halmos, or a confirmed
    Foundry PoC) becomes one Finding. The judge treats these as the ground
    truth the audit narrative must be consistent with. A confirmed PoC carries
    its measured ``profit_wei`` as the strongest artifact.
    """
    target = str(agent_result.get("target", "") or "web3-audit")
    session = ScanSession(target=target)
    for key in _FINDING_KEYS:
        for finding in agent_result.get(key, []) or []:
            if not isinstance(finding, dict):
                continue
            tier = immunefi_tier(finding)
            evidence: list[Any] = []
            profit = finding.get("profit_wei")
            if profit is not None:
                evidence.append(f"profit_wei={profit}")
            for field_name in ("description", "impact", "confidence", "test"):
                value = finding.get(field_name)
                if value:
                    evidence.append(f"{field_name}={value}")
            session.add_finding(
                severity=Severity(_TIER_TO_INTERNAL.get(tier, "INFO")),
                title=_finding_title(finding),
                description=str(finding.get("description", "")).strip(),
                agent="web3",
                target=target,
                evidence=evidence or None,
            )
    return session


def judge_web3_findings(
    report_text: str,
    agent_result: dict[str, Any],
    llm: LLMClient,
    *,
    threshold: float = 0.7,
    judge_model: Optional[str] = None,
) -> JudgeVerdict:
    """Cross-check a Web3 audit narrative against raw detector evidence.

    ``report_text`` is the human-facing draft (typically an Immunefi
    submission); ``agent_result`` is a Web3 agent local-audit result. Returns
    a JudgeVerdict. Delegates to the shared ``judge_report``, inheriting its
    graceful-degradation contract: the audit is never hard-failed by the judge.
    """
    session = _evidence_session(agent_result)
    return judge_report(
        report_text,
        session,
        llm,
        threshold=threshold,
        judge_model=judge_model,
        agent_name="web3.judge",
    )
