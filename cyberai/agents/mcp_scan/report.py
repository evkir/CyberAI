"""MCP red-team report — OWASP MCP Top 10 + MITRE ATLAS mapping over a scan result.

Pure representation layer over the dict returned by :meth:`MCPScanAgent.run`.
Each analysis stage (poisoning, over-privilege, trust, attestation, exposure,
and the optional MST low-level fuzzer) is mapped onto an OWASP MCP Top 10
category (``MCPxx:2025``) and a MITRE ATLAS technique id, then rendered as a
Markdown report plus a structured dict. The function adds no findings — the
analysis stages own those — and is side-effect free.

Taxonomy references (verified against the live sources):

* OWASP MCP Top 10 (beta, 2025 IDs): https://owasp.org/www-project-mcp-top-10/
* MITRE ATLAS techniques (v5.4.0): https://atlas.mitre.org/
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Tuple

from cyberai.agents.mcp_scan.scorecard import build_mcp_scorecard
from cyberai.core.scan_session import Severity

_ORDER = [
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFO.value,
]
_RANK = {sev: i for i, sev in enumerate(_ORDER)}


def _worst(severities: List[str]) -> str:
    """Return the highest-severity value in the list, or INFO if empty."""
    ranked = [s for s in severities if s in _RANK]
    if not ranked:
        return Severity.INFO.value
    return min(ranked, key=lambda s: _RANK[s])


@dataclass
class RiskRow:
    """One stage mapped onto OWASP MCP Top 10 + MITRE ATLAS."""

    stage: str
    owasp_id: str
    owasp_name: str
    atlas_id: str
    atlas_name: str
    severity: str
    signals: int
    tools: List[str] = field(default_factory=list)


def _tool_stage(summary: Dict[str, Any], count_key: str) -> Tuple[str, int, List[str], List[str]]:
    """Extract (worst_severity, signal_count, tool_names, severities) for a per-tool stage."""
    tools = summary.get("tools", []) or []
    sevs = [str(t.get("severity", Severity.INFO.value)) for t in tools]
    names = [str(t.get("tool_name", "?")) for t in tools]
    return _worst(sevs), int(summary.get(count_key, 0)), names, sevs


def _endpoint_stage(summary: Dict[str, Any], flag_key: str) -> Tuple[str, int, List[str]]:
    """Extract (severity, signal_count, severities) for an endpoint-level stage."""
    scan = summary.get("scan", {}) or {}
    flagged = bool(summary.get(flag_key))
    sev = str(scan.get("severity", Severity.INFO.value)) if flagged else Severity.INFO.value
    return sev, (1 if flagged else 0), ([sev] if flagged else [])


def build_risk_rows(result: Dict[str, Any]) -> List[RiskRow]:
    """Map every analysis stage in a scan result onto OWASP MCP + ATLAS rows."""
    rows: List[RiskRow] = []

    p_sev, p_sig, p_names, _ = _tool_stage(result.get("poisoning", {}), "suspicious")
    rows.append(
        RiskRow(
            "tool-poisoning",
            "MCP03:2025",
            "Tool Poisoning",
            "AML.T0110",
            "AI Agent Tool Poisoning",
            p_sev,
            p_sig,
            p_names,
        )
    )

    o_sev, o_sig, o_names, _ = _tool_stage(result.get("overprivilege", {}), "overprivileged")
    rows.append(
        RiskRow(
            "over-privilege",
            "MCP02:2025",
            "Privilege Escalation via Scope Creep",
            "AML.T0086",
            "Exfiltration via AI Agent Tool Invocation",
            o_sev,
            o_sig,
            o_names,
        )
    )

    t_sev, t_sig, t_names, _ = _tool_stage(result.get("trust", {}), "shadowing")
    rows.append(
        RiskRow(
            "trust-propagation",
            "MCP06:2025",
            "Intent Flow Subversion",
            "AML.T0051",
            "LLM Prompt Injection",
            t_sev,
            t_sig,
            t_names,
        )
    )

    a_sev, a_sig, _ = _endpoint_stage(result.get("attestation", {}), "unauthenticated")
    rows.append(
        RiskRow(
            "attestation",
            "MCP07:2025",
            "Insufficient Authentication & Authorization",
            "-",
            "-",
            a_sev,
            a_sig,
        )
    )

    e_sev, e_sig, _ = _endpoint_stage(result.get("exposure", {}), "exposed")
    rows.append(
        RiskRow(
            "exposure",
            "MCP07:2025",
            "Insufficient Authentication & Authorization",
            "AML.T0040",
            "AI Model Inference API Access",
            e_sev,
            e_sig,
        )
    )

    mst = result.get("mst", []) or []
    if mst:
        m_sevs = [str(m.get("severity", Severity.INFO.value)) for m in mst]
        m_names = [str(m.get("check", "?")) for m in mst]
        rows.append(
            RiskRow(
                "mst-fuzzing",
                "MCP05:2025",
                "Command Injection & Execution",
                "AML.T0110",
                "AI Agent Tool Poisoning",
                _worst(m_sevs),
                len(mst),
                m_names,
            )
        )

    return rows


def _severity_summary(result: Dict[str, Any], rows: List[RiskRow]) -> Dict[str, int]:
    """Histogram of individual flagged-item severities across all stages."""
    sevs: List[str] = []
    for key in ("poisoning", "overprivilege", "trust"):
        sevs += [
            str(t.get("severity", Severity.INFO.value))
            for t in result.get(key, {}).get("tools", []) or []
        ]
    att = result.get("attestation", {})
    if att.get("unauthenticated"):
        sevs.append(str(att.get("scan", {}).get("severity", Severity.INFO.value)))
    exp = result.get("exposure", {})
    if exp.get("exposed"):
        sevs.append(str(exp.get("scan", {}).get("severity", Severity.INFO.value)))
    sevs += [str(m.get("severity", Severity.INFO.value)) for m in result.get("mst", []) or []]
    return {level: sevs.count(level) for level in _ORDER}


def build_mcp_report(result: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Render an MCP red-team report (Markdown, structured dict) from a scan result.

    ``result`` is the dict returned by :meth:`MCPScanAgent.run`. The Markdown
    embeds the STRIDE scorecard; the dict is machine-readable for export.
    """
    rows = build_risk_rows(result)
    summary = _severity_summary(result, rows)
    endpoint = result.get("endpoint", "?")

    active = [r for r in rows if r.signals > 0]
    owasp_hit = sorted({r.owasp_id for r in active})
    atlas_hit = sorted({r.atlas_id for r in active if r.atlas_id != "-"})

    lines: List[str] = []
    lines.append(f"# MCP Red-Team Report - `{endpoint}`")
    lines.append("")
    lines.append(f"- transport: {result.get('transport', '?')}")
    lines.append(f"- connected: {result.get('connected', False)}")
    lines.append(f"- tools probed: {result.get('tools', 0)}")
    if result.get("error"):
        lines.append(f"- error: {result.get('error')}")
    lines.append("")
    lines.append("## Severity summary")
    lines.append("")
    for level in _ORDER:
        lines.append(f"- {level}: {summary[level]}")
    lines.append("")
    lines.append("## OWASP MCP Top 10 / MITRE ATLAS mapping")
    lines.append("")
    lines.append("| Stage | OWASP MCP Top 10 | MITRE ATLAS | Severity | Signals |")
    lines.append("| --- | --- | --- | --- | --- |")
    for r in rows:
        owasp = f"{r.owasp_id} {r.owasp_name}"
        atlas = f"{r.atlas_id} {r.atlas_name}" if r.atlas_id != "-" else "-"
        lines.append(f"| {r.stage} | {owasp} | {atlas} | {r.severity} | {r.signals} |")
    lines.append("")
    flagged_rows = [r for r in active if r.tools]
    if flagged_rows:
        lines.append("### Flagged items")
        lines.append("")
        for r in flagged_rows:
            lines.append(f"- {r.stage}: {', '.join(r.tools)}")
        lines.append("")
    lines.append('> MCP06 is titled "Intent Flow Subversion" in the OWASP index and')
    lines.append('> "Prompt Injection via Contextual Payloads" in the README (beta drift).')
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(build_mcp_scorecard(result))

    markdown = "\n".join(lines)
    data: Dict[str, Any] = {
        "endpoint": endpoint,
        "transport": result.get("transport"),
        "connected": result.get("connected", False),
        "tools_probed": result.get("tools", 0),
        "severity_summary": summary,
        "owasp_categories": owasp_hit,
        "atlas_techniques": atlas_hit,
        "risks": [asdict(r) for r in rows],
    }
    return markdown, data


def render_mcp_report_json(result: Dict[str, Any]) -> str:
    """Convenience: the structured report as a JSON string."""
    _, data = build_mcp_report(result)
    return json.dumps(data, indent=2, default=str)
