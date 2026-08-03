from datetime import datetime, timezone

from cyberai.core.session import PentestSession, Severity

from .domains import group_by_domain

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "🔵",
}


# Beyond this, a value is a wall of text in the middle of a finding rather
# than something read at a glance; the full copy stays in the JSON export.
_INLINE_LIMIT = 160
_BLOCK_LIMIT = 1200
# Enough to see the shape of a list without scrolling past the next finding.
_LIST_LIMIT = 15


def _render_value(key: str, value: object) -> list[str]:
    """One field of structured data: inline when short, fenced when not."""
    text = str(value)
    if len(text) <= _INLINE_LIMIT and "\n" not in text:
        return [f"**{key}:** `{text}`  "]
    return ["", f"**{key}:**", "", "```", text[:_BLOCK_LIMIT], "```", ""]


def _render_data(data: object) -> list[str]:
    """Structured finding data, as fields rather than a printed dictionary.

    A dict rendered with str() arrives as one long line of Python repr, quotes
    escaped and newlines literal. The evidence that justifies the finding is
    in there, and nobody reads it.
    """
    if not data:
        return []
    if isinstance(data, (list, tuple)):
        # A list is a set of observations, not one field repeated: labelling
        # each entry turns eight endpoints into eight headings called "Data".
        items = [str(x) for x in data if x not in (None, "", [], {})]
        if not items:
            return []
        if all(len(x) <= _INLINE_LIMIT and "\n" not in x for x in items):
            shown = items[:_LIST_LIMIT]
            rendered = [f"- `{x}`" for x in shown]
            if len(items) > _LIST_LIMIT:
                # A scan against a tarpit returns hundreds of ports. Printing
                # them all buries every real finding below the fold; the full
                # list is in the JSON export, which is where a tool reads it.
                rendered.append(f"- *… and {len(items) - _LIST_LIMIT} more*")
            return rendered + [""]
        return ["", "```", "\n".join(items)[:_BLOCK_LIMIT], "```", ""]
    if not isinstance(data, dict):
        return _render_value("Data", data)
    lines: list[str] = []
    for key, value in data.items():
        if value in (None, "", [], {}):
            continue
        lines += _render_value(str(key).replace("_", " ").capitalize(), value)
    if lines and not lines[-1].startswith("```") and lines[-1] != "":
        lines.append("")
    return lines


def render_markdown(session: PentestSession) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = session.findings

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    low = [f for f in findings if f.severity == Severity.LOW]
    info = [f for f in findings if f.severity == Severity.INFO]

    lines = [
        "# CyberAI Pentest Report",
        "",
        f"**Target:** `{session.target}`  ",
        f"**Session ID:** `{session.session_id}`  ",
        f"**Generated:** {now}  ",
        f"**Status:** {session.state.value.upper()}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {len(critical)} |",
        f"| 🟠 High     | {len(high)} |",
        f"| 🟡 Medium   | {len(medium)} |",
        f"| 🟢 Low      | {len(low)} |",
        f"| 🔵 Info     | {len(info)} |",
        f"| **Total**   | **{len(findings)}** |",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    grouped = group_by_domain(findings)
    # Domain headings appear only once a scan actually spans more than one
    # surface; a plain network run renders exactly as it always has.
    split = len(grouped) > 1
    heading = "####" if split else "###"
    index = 0

    for domain, domain_findings in grouped.items():
        if split:
            lines += [f"### {domain} ({len(domain_findings)})", ""]

        for finding in domain_findings:
            index += 1
            emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
            lines += [
                f"{heading} {index}. {emoji} {finding.title}",
                "",
                f"**Severity:** {finding.severity.value}  ",
                f"**Target:** `{session.target}`  ",
                f"**Agent:** {finding.agent}  ",
                f"**Timestamp:** {finding.timestamp}",
                "",
                f"{finding.description}",
                "",
            ]
            if getattr(finding, "confidence", 1.0) < 1.0:
                lines.append(f"**Confidence:** {finding.confidence:.0%} ⚠️")
                lines.append("")
            if finding.cve:
                lines.append(f"**CVE:** `{finding.cve}`")
                lines.append("")
            if finding.data:
                lines += _render_data(finding.data)
            # Evidence is what makes a finding checkable, and it was reaching
            # the JSON export but never the page a human opens.
            elif finding.evidence:
                lines += _render_data(finding.evidence)
            lines += ["---", ""]

    lines += [
        "## Summary",
        "",
        f"Total findings: {len(findings)}",
        f"Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}",
    ]
    if split:
        lines.append(" | ".join(f"{d}: {len(v)}" for d, v in grouped.items()))
    lines += [
        "",
        "*Generated by CyberAI*",
    ]

    return "\n".join(lines)
