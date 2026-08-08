"""
HTML report renderer — converts KB data into a styled HTML report.
"""

from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

TEMPLATE_PATH = Path(__file__).parent / "templates" / "report.html"

SEVERITY_CLASS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
}


def render_html_report(
    session_summary: Dict[str, Any],
    kb: Dict[str, Any],
    output_path: str = "report.html",
    findings: Optional[List[Any]] = None,
) -> str:
    """
    Render full HTML report from session summary + KB data.
    Returns path to written file.
    """
    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    attack_paths = _get_attack_paths(kb)
    chain = _get_chain(kb)
    ai_analysis = _get_ai_analysis(kb)

    replacements = {
        "{target}": _escape(session_summary.get("target", "")),
        "{session_id}": session_summary.get("session_id", ""),
        "{generated_at}": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "{state}": session_summary.get("state", ""),
        "{duration_s}": str(session_summary.get("duration_s", "")),
        "{phases_html}": _render_phases(session_summary.get("phases", [])),
        "{web_exploitation_html}": _render_web_exploitation(kb),
        "{attack_paths_html}": _render_attack_paths(attack_paths),
        "{chain_html}": _render_chain(chain),
        "{ai_analysis}": _escape(ai_analysis),
        # Last on purpose: substitution walks the whole template once per key,
        # so a finding whose text contains a placeholder name cannot be
        # rewritten by a later pass.
        "{findings_html}": _render_findings(findings or []),
    }
    html = template
    for key, val in replacements.items():
        html = html.replace(key, val)

    out = Path(output_path)
    # The caller may point anywhere; a writer that cannot create its own
    # directory works only while some other writer happens to run first.
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return output_path


def _render_web_exploitation(kb: Dict[str, Any]) -> str:
    """What the web phase touched, and what it could not answer for.

    Markdown grew this section; the HTML page did not, and twelve contract
    tests stayed green because every one of them read the markdown file. A
    reader who opens the page instead sees the confirmed findings and no
    sign that anything else on the HTTP surface was left unanswered.
    """
    report = kb.get("exploit.web")
    if not isinstance(report, dict):
        return ""
    groups = [
        ("Untested -- refused without a credential", "unauthorized_params", _param_row),
        ("Value not read", "inert_params", _param_row),
        ("Skipped as state-changing", "destructive_endpoints", _endpoint_row),
        ("Not routed", "phantom_endpoints", _endpoint_row),
        ("Enumerable identifier", "enumerable_params", _param_row),
    ]
    present = [
        (t, [x for x in (report.get(k) or []) if isinstance(x, dict)], r) for t, k, r in groups
    ]
    present = [(t, items, r) for t, items, r in present if items]
    tested = report.get("endpoints_tested", 0)
    if not (tested or present):
        return ""
    parts = [
        "<h2>Web Exploitation</h2>",
        f"<p>Endpoints tested: {_escape(str(tested))} | "
        f"Requests sent: {_escape(str(report.get('requests_sent', 0)))} | "
        f"Confirmed: {_escape(str(report.get('confirmed', 0)))}</p>",
    ]
    for title, items, row in present:
        parts.append(f"<h3>{_escape(title)} ({len(items)})</h3>")
        parts.append("<ul>" + "".join(row(i) for i in items) + "</ul>")
    return "\n".join(parts)


def _param_row(item: Dict[str, Any]) -> str:
    return (
        f"<li><code>{_escape(str(item.get('method', '')))} "
        f"{_escape(str(item.get('url', '')))}</code> — "
        f"{_escape(str(item.get('parameter', '')))}</li>"
    )


def _endpoint_row(item: Dict[str, Any]) -> str:
    return (
        f"<li><code>{_escape(str(item.get('method', '')))} "
        f"{_escape(str(item.get('url', '')))}</code></li>"
    )


# ── section renderers ─────────────────────────────────────────────────


def _render_phases(phases: List[Dict]) -> str:
    if not phases:
        return "<p>No phases recorded.</p>"
    parts = []
    for p in phases:
        status = "success" if p.get("success") else "failed"
        icon = "✓" if p.get("success") else "✗"
        error = (
            f"<br><span style='color:#ff4444'>Error: {p['error']}</span>" if p.get("error") else ""
        )
        parts.append(
            f'<div class="phase {status}">'
            f"<strong>{icon} {p['phase'].upper()}</strong> — "
            f"{p['duration_s']:.1f}s{error}"
            f"</div>"
        )
    return "\n".join(parts)


def _render_attack_paths(paths: List[Dict]) -> str:
    if not paths:
        return "<p>No attack paths identified.</p>"

    rows = []
    for p in paths:
        sev = p.get("severity_tier", "INFO")
        cls = SEVERITY_CLASS.get(sev, "low")
        prob = p.get("success_probability", 0)
        tags = " ".join(f'<span class="tag">{t}</span>' for t in p.get("tags", []))
        rows.append(
            f"<tr>"
            f"<td>{_escape(p.get('cve_id', ''))}</td>"
            f"<td class='{cls}'>{sev}</td>"
            f"<td>{_escape(p.get('attack_vector', ''))}</td>"
            f"<td>{prob:.0%}</td>"
            f"<td>{_escape(p.get('technique', ''))}</td>"
            f"<td>{_escape(p.get('remediation', ''))}</td>"
            f"<td>{tags}</td>"
            f"</tr>"
        )

    header = (
        "<table class='cve-table'>"
        "<tr><th>CVE</th><th>Severity</th><th>Vector</th>"
        "<th>Probability</th><th>Technique</th>"
        "<th>Remediation</th><th>Tags</th></tr>"
    )
    return header + "\n".join(rows) + "</table>"


def _render_chain(chain: Dict) -> str:
    if not chain:
        return "<p>No exploit chain built.</p>"
    steps = chain.get("steps", [])
    if not steps:
        return f"<p>{_escape(chain.get('summary', ''))}</p>"

    parts = []
    for i, step in enumerate(steps):
        parts.append(
            f'<span class="chain-step">'
            f"<strong>{_escape(step.get('phase', ''))}</strong><br>"
            f"<small>{_escape(step.get('cve_id', ''))}</small><br>"
            f'<small style="color:#888">{_escape(step.get("technique", "")[:40])}</small>'
            f"</span>"
        )
        if i < len(steps) - 1:
            parts.append('<span class="arrow">→</span>')

    summary = chain.get("summary", "")
    return f'<p style="color:#88cc88">Chain: {_escape(summary)}</p>' + "".join(parts)


def _severity_name(finding: Any) -> str:
    sev = getattr(finding, "severity", "")
    return str(getattr(sev, "value", sev)).upper()


_DETAIL_LIMIT = 8
_VALUE_LIMIT = 600


def _detail_rows(payload: Any) -> str:
    """Finding details as fields, not as a printed Python object.

    The web exploit path stores one dict in both data and evidence, and a
    list of dicts stringified is a repr on one line: quotes escaped, the
    proof buried mid-string. Measured on a real finding, the snippet that
    justifies the report was past the fold of an unreadable line.
    """
    if not payload:
        return ""
    if isinstance(payload, (list, tuple)):
        items = [x for x in payload if x not in (None, "", [], {})]
        if not items:
            return ""
        return "".join(_detail_rows(x) for x in items[:_DETAIL_LIMIT])
    if not isinstance(payload, dict):
        return f"<pre>{_escape(str(payload)[:_VALUE_LIMIT])}</pre>"
    rows = []
    for key, value in payload.items():
        if value in (None, "", [], {}):
            continue
        label = _escape(str(key).replace("_", " ").capitalize())
        rows.append(f"<tr><td>{label}</td><td>{_escape(str(value)[:_VALUE_LIMIT])}</td></tr>")
    if not rows:
        return ""
    return "<table class='cve-table'>" + "".join(rows) + "</table>"


def _render_findings(findings: List[Any]) -> str:
    """The findings themselves, which this report never carried.

    Phases, attack paths and the AI paragraph were rendered; a confirmed SQLi
    reached the JSON export and the Markdown and stopped there. The page a
    human opens is the one that has to name it.
    """
    if not findings:
        return "<p>No findings recorded.</p>"

    parts = []
    for index, finding in enumerate(findings, 1):
        sev = _severity_name(finding)
        cls = SEVERITY_CLASS.get(sev, "low")
        meta = [f"<strong>Agent:</strong> {_escape(getattr(finding, 'agent', ''))}"]
        target = getattr(finding, "target", None)
        if target:
            meta.append(f"<strong>Target:</strong> {_escape(target)}")
        cve = getattr(finding, "cve", None)
        if cve:
            meta.append(f"<strong>CVE:</strong> {_escape(cve)}")
        confidence = getattr(finding, "confidence", 1.0)
        if confidence < 1.0:
            meta.append(f"<strong>Confidence:</strong> {confidence:.0%}")
        parts.append(
            f'<div class="phase">'
            f"<h3>{index}. {_escape(getattr(finding, 'title', ''))} "
            f"<span class='{cls}'>[{sev}]</span></h3>"
            f"<p>{_escape(getattr(finding, 'description', ''))}</p>"
            f"<p><small>{' | '.join(meta)}</small></p>"
            # data and evidence hold the same dict on a web finding; rendering
            # both prints the proof twice.
            f"{_detail_rows(getattr(finding, 'data', None) or getattr(finding, 'evidence', None))}"
            f"</div>"
        )
    return "\n".join(parts)


# ── kb helpers ────────────────────────────────────────────────────────


def _get_attack_paths(kb: Dict) -> List[Dict]:
    exploit = kb.get("exploit", {})
    paths = exploit.get("attack_paths", [])
    # enrich if not already enriched
    if paths and "severity_tier" not in paths[0]:
        from cyberai.agents.exploit.attack_metadata import enrich_all

        enriched = enrich_all(paths)
        return [e.to_dict() for e in enriched]
    return paths


def _get_chain(kb: Dict) -> Dict:
    return kb.get("exploit", {}).get("exploit_chain", {})


def _get_ai_analysis(kb: Dict) -> str:
    return kb.get("exploit", {}).get("ai_analysis", "No AI analysis available.")


def _escape(text: str) -> str:
    """Minimal HTML escape."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
