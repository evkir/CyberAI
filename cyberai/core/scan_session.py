"""
ScanSession — single source of truth for a pentest scan lifecycle.

This module holds:
  * ScanSession — the lifecycle object (created → running → completed/failed)
  * ScanState, ScanPhase — state enums
  * PhaseResult — per-phase outcome record
  * Severity, Finding — vulnerability finding model (moved here from session.py)

The legacy `cyberai.core.session` module re-exports everything from here
for backward compatibility; new code should import from `scan_session`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cyberai.core.knowledge_base import KnowledgeBase

# ── enums ─────────────────────────────────────────────────────────────


class ScanState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    RECON = "recon"
    INTEL = "intel"
    PLAN = "plan"
    EXPLOIT = "exploit"
    REPORT = "report"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhase(str, Enum):
    RECON = "recon"
    INTEL = "intel"
    PLAN = "plan"
    EXPLOIT = "exploit"
    REPORT = "report"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ── models ────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """
    A single vulnerability finding.

    Fields target/evidence/cve_ids are present so agents
    were already passing these but the dataclass didn't accept them.
    """

    id: int
    severity: Severity
    title: str
    description: str
    timestamp: str
    agent: str

    # Legacy single-CVE field (kept for backward compat with old callers)
    cve: Optional[str] = None
    # New: list of CVEs (some findings reference multiple)
    cve_ids: List[str] = field(default_factory=list)
    # New: target this finding was made against (host, URL, contract addr)
    target: Optional[str] = None
    # New: artifacts proving the finding (nmap output, request/response, etc.)
    evidence: List[Any] = field(default_factory=list)
    # Free-form structured data
    data: Any = None
    # Confidence this finding is real, 0..1. 1.0 = fully evidenced (default).
    # Lowered by the LLM-as-Judge / agents when evidence is weak.
    confidence: float = 1.0

    def __post_init__(self) -> None:
        # Keep `cve` and `cve_ids` in sync for callers that use either
        if self.cve and not self.cve_ids:
            self.cve_ids = [self.cve]
        elif self.cve_ids and not self.cve:
            self.cve = self.cve_ids[0]


@dataclass
class PhaseResult:
    phase: ScanPhase
    success: bool
    started_at: str
    ended_at: str
    duration_s: float
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


# ── session ───────────────────────────────────────────────────────────


@dataclass
class ScanSession:
    target: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    state: ScanState = ScanState.CREATED
    created_at: str = field(default_factory=lambda: _now())
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    phases: List[PhaseResult] = field(default_factory=list)
    kb: KnowledgeBase = field(default_factory=KnowledgeBase)
    errors: List[str] = field(default_factory=list)
    authorized_scope: List[str] = field(default_factory=list)

    # Findings live on the session to unify with the former PentestSession
    findings: List[Finding] = field(default_factory=list)

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> None:
        self.state = ScanState.RUNNING
        self.started_at = _now()

    def complete(self) -> None:
        self.state = ScanState.COMPLETED
        self.ended_at = _now()

    def fail(self, reason: str) -> None:
        self.state = ScanState.FAILED
        self.ended_at = _now()
        self.errors.append(reason)

    def cancel(self) -> None:
        self.state = ScanState.CANCELLED
        self.ended_at = _now()

    def set_phase(self, phase: ScanPhase) -> None:
        self.state = ScanState(phase.value)

    # ── findings ──────────────────────────────────────────────────────

    def add_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        agent: str,
        target: Optional[str] = None,
        cve: Optional[str] = None,
        cve_ids: Optional[List[str]] = None,
        evidence: Optional[List[Any]] = None,
        data: Any = None,
    ) -> Finding:
        f = Finding(
            id=len(self.findings) + 1,
            severity=severity,
            title=title,
            description=description,
            timestamp=_now(),
            agent=agent,
            target=target or self.target,
            cve=cve,
            cve_ids=cve_ids or [],
            evidence=evidence or [],
            data=data,
        )
        self.findings.append(f)
        return f

    # ── phase tracking ────────────────────────────────────────────────

    def record_phase(
        self,
        phase: ScanPhase,
        success: bool,
        started: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> PhaseResult:
        ended = _now()
        duration = _delta(started, ended)
        result = PhaseResult(
            phase=phase,
            success=success,
            started_at=started,
            ended_at=ended,
            duration_s=duration,
            data=data or {},
            error=error,
        )
        self.phases.append(result)
        return result

    # ── kb helpers ────────────────────────────────────────────────────

    def kb_set(self, key: str, value: Any) -> None:
        self.kb[key] = value

    def kb_get(self, key: str, default: Any = None) -> Any:
        return self.kb.get(key, default)

    # ── summary ───────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        duration = None
        if self.started_at and self.ended_at:
            duration = round(_delta(self.started_at, self.ended_at), 1)

        severity_counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            severity_counts[f.severity.value] += 1

        return {
            "session_id": self.session_id,
            "target": self.target,
            "state": self.state.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_s": duration,
            "phases": [_phase_summary(p) for p in self.phases],
            "findings_total": len(self.findings),
            "severity_breakdown": severity_counts,
            "errors": self.errors,
            "kb_keys": list(self.kb.keys()),
        }

    # ── full serialization for replay ─────────────────────────────────

    def to_json(self, indent: int = 2) -> str:
        """Full session export including KB values, findings and phases.

        Non-JSON-native values fall back to str(). Restorable via from_json().
        """
        payload = {
            "session_id": self.session_id,
            "target": self.target,
            "state": self.state.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "authorized_scope": list(self.authorized_scope),
            "errors": list(self.errors),
            "findings": [_finding_to_dict(f) for f in self.findings],
            "phases": [_phase_to_dict(p) for p in self.phases],
            "kb": self.kb.snapshot(),
        }
        return json.dumps(payload, indent=indent, default=str)

    @classmethod
    def from_json(cls, raw: str) -> "ScanSession":
        """Rebuild a ScanSession from to_json() output.

        Findings/phases are restored as dataclasses; KB values are restored
        verbatim from the snapshot. Timestamps and ids are preserved.
        """
        data = json.loads(raw)
        session = cls(
            target=data["target"],
            session_id=data.get("session_id", str(uuid.uuid4())[:8]),
        )
        session.state = ScanState(data.get("state", "created"))
        session.created_at = data.get("created_at", session.created_at)
        session.started_at = data.get("started_at")
        session.ended_at = data.get("ended_at")
        session.authorized_scope = list(data.get("authorized_scope", []))
        session.errors = list(data.get("errors", []))
        session.kb = KnowledgeBase.from_snapshot(data.get("kb", {}))
        for fd in data.get("findings", []):
            session.findings.append(_finding_from_dict(fd))
        for pd in data.get("phases", []):
            session.phases.append(_phase_from_dict(pd))
        return session

    def __repr__(self) -> str:
        return (
            f"ScanSession(id={self.session_id}, "
            f"target={self.target}, state={self.state.value}, "
            f"findings={len(self.findings)})"
        )


# ── helpers ───────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _delta(start: str, end: str) -> float:
    try:
        t0 = datetime.fromisoformat(start)
        t1 = datetime.fromisoformat(end)
        return (t1 - t0).total_seconds()
    except Exception:
        return 0.0


def _phase_summary(p: PhaseResult) -> Dict[str, Any]:
    return {
        "phase": p.phase.value,
        "success": p.success,
        "duration_s": p.duration_s,
        "error": p.error,
    }


# ── (de)serialization helpers for replay ──────────────────────────────


def _finding_to_dict(f: "Finding") -> Dict[str, Any]:
    d = asdict(f)
    if isinstance(d.get("severity"), Severity):
        d["severity"] = f.severity.value
    elif hasattr(f.severity, "value"):
        d["severity"] = f.severity.value
    return d


def _finding_from_dict(d: Dict[str, Any]) -> "Finding":
    data = dict(d)
    sev = data.get("severity", "INFO")
    data["severity"] = sev if isinstance(sev, Severity) else Severity(str(sev).upper())
    return Finding(**data)


def _phase_to_dict(p: "PhaseResult") -> Dict[str, Any]:
    d = asdict(p)
    if hasattr(p.phase, "value"):
        d["phase"] = p.phase.value
    return d


def _phase_from_dict(d: Dict[str, Any]) -> "PhaseResult":
    data = dict(d)
    ph = data.get("phase")
    data["phase"] = ph if isinstance(ph, ScanPhase) else ScanPhase(str(ph))
    return PhaseResult(**data)
