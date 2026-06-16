"""LLM-as-Judge — validates report claims against knowledge-base evidence.

A second (optionally more powerful) LLM cross-checks every claim in the
generated report against the evidence actually present in the session KB.
It returns a hallucination score in [0, 1] and a list of unsupported
claims. Flag-gated in ReportAgent (use_judge, default False) — the
deterministic report is never blocked by judge failures.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from cyberai.core.llm_client import LLMClient
from cyberai.core.scan_session import ScanSession


class JudgeVerdict(BaseModel):
    """Structured verdict returned by the judge LLM."""

    hallucination_score: float = 0.0
    supported: bool = True
    unsupported_claims: List[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("hallucination_score", mode="before")
    @classmethod
    def _clamp(cls, v: Any) -> float:
        """Clamp to [0,1] BEFORE type validation — the LLM may over/undershoot.

        A misbehaving judge returning 1.2 must not crash the report; we squash
        it into range rather than raising, matching the graceful-degradation
        contract of the whole judge path.
        """
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.0


# Flat JSON Schema for structured_call (OpenAI strict-friendly: no nesting).
VERDICT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "hallucination_score": {
            "type": "number",
            "description": "0.0 = every claim backed by evidence; 1.0 = all fabricated.",
        },
        "supported": {
            "type": "boolean",
            "description": "True if the report is sufficiently grounded in evidence.",
        },
        "unsupported_claims": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Claims in the report with no matching KB evidence.",
        },
        "notes": {"type": "string", "description": "Brief reviewer notes."},
    },
    "required": ["hallucination_score", "supported", "unsupported_claims", "notes"],
}

JUDGE_SYSTEM = (
    "You are a strict security-report reviewer. You are given a penetration-"
    "test report and the raw EVIDENCE collected during the scan (findings, "
    "CVE IDs, tool artifacts). Your job: detect hallucinations. A claim is "
    "UNSUPPORTED if it asserts a vulnerability, CVE, port, or impact that "
    "does not appear in the evidence. Do NOT reward fluency. Score "
    "hallucination_score in [0,1]: 0 means every claim is backed by "
    "evidence, 1 means the report is fabricated. List each unsupported "
    "claim verbatim. Respond ONLY via the structured schema."
)


def _collect_evidence(session: ScanSession) -> Dict[str, Any]:
    """Pull the ground-truth evidence the report must be consistent with."""
    findings = []
    for f in session.findings:
        findings.append(
            {
                "id": f.id,
                "title": f.title,
                "severity": getattr(f.severity, "value", str(f.severity)),
                "cve_ids": list(f.cve_ids),
                "target": f.target,
                "evidence": [str(e)[:500] for e in (f.evidence or [])],
            }
        )
    return {
        "target": session.target,
        "findings": findings,
    }


@contextmanager
def _judge_model(llm: LLMClient, model: Optional[str]):
    """Temporarily swap the LLM model to the (more powerful) judge model."""
    if not model:
        yield
        return
    original = llm.config.model
    llm.config.model = model
    try:
        yield
    finally:
        llm.config.model = original


def judge_report(
    report_text: str,
    session: ScanSession,
    llm: LLMClient,
    *,
    threshold: float = 0.7,
    judge_model: Optional[str] = None,
    agent_name: str = "report.judge",
) -> JudgeVerdict:
    """Cross-check `report_text` against session evidence via a second LLM.

    Returns a JudgeVerdict. On ANY failure returns a graceful pass-through
    verdict (score=0.0, supported=True) so the report pipeline never breaks.
    `supported` is recomputed from the score against `threshold` regardless
    of what the model claimed.
    """
    if llm is None:
        return JudgeVerdict(notes="judge unavailable: no LLM client")

    evidence = _collect_evidence(session)
    messages = [
        {
            "role": "user",
            "content": (
                "REPORT:\n"
                f"{report_text}\n\n"
                "EVIDENCE (ground truth):\n"
                f"{json.dumps(evidence, indent=2, default=str)}"
            ),
        }
    ]

    try:
        with _judge_model(llm, judge_model):
            raw = llm.structured_call(
                messages,
                schema=VERDICT_SCHEMA,
                schema_name="judge_verdict",
                description="Hallucination verdict for a pentest report.",
                system=JUDGE_SYSTEM,
                agent_name=agent_name,
            )
        verdict = JudgeVerdict.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — judge must never hard-fail
        return JudgeVerdict(notes=f"judge unavailable: {exc}")

    # Threshold is authoritative — don't trust the model's own `supported`.
    verdict.supported = verdict.hallucination_score < threshold
    return verdict
