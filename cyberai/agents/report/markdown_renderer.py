from collections.abc import Callable
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


def _listed(entries: list, line_for: Callable[[dict], str]) -> list[str]:
    """Walk a list of records into bullets, capped and free of malformed rows.

    The cap and the skip are the same for every list in this section; only the
    shape of the line differs. Written once because a second copy of the two
    boundary branches is a second place to forget one.
    """
    lines: list[str] = []
    for item in entries[:_LIST_LIMIT]:
        if not isinstance(item, dict):
            continue
        lines.append(line_for(item))
    if len(entries) > _LIST_LIMIT:
        lines.append(f"- *... and {len(entries) - _LIST_LIMIT} more*")
    return lines


def _param_line(item: dict) -> str:
    """Where the parameter is, what it is called, how it travels, how it was found.

    The verdict on a name parsed out of a minified bundle and on a name a spec
    declares reads identically, and the two do not deserve equal weight. The
    source is omitted when absent rather than printed empty, so a report from
    before it was recorded does not grow a dangling comma.
    """
    where = item.get("transport", "")
    source = item.get("source", "")
    if source:
        where = f"{where}, {source}"
    return (
        f"- `{item.get('method', '')} {item.get('url', '')}` "
        f"-- parameter `{item.get('parameter', '')}` ({where})"
    )


def _endpoint_line(item: dict) -> str:
    """The verb and the address, nothing else.

    Kept apart from `_param_line` because an endpoint has no parameter and no
    transport, and borrowing that shape would print empty backticks for both.
    """
    return f"- `{item.get('method', '')} {item.get('url', '')}`"


def _param_lines(entries: list) -> list[str]:
    return _listed(entries, _param_line)


def _endpoint_lines(entries: list) -> list[str]:
    return _listed(entries, _endpoint_line)


def _render_ai_analysis(session: PentestSession) -> list[str]:
    """The model's reading of the phase, if a model was asked.

    Only the HTML report carried this. A reader who opens the Markdown -- the
    format committed to repositories and pasted into tickets -- saw the
    findings but never the analysis that interpreted them, which is the part
    that says which finding to chase first.
    """
    kb = getattr(session, "kb", None)
    exploit = kb.get("exploit") if kb is not None else None
    if not isinstance(exploit, dict):
        return []
    analysis = exploit.get("ai_analysis")
    # A non-string, or the skip notice from a run with no model wired, is not
    # analysis; a heading over either would promise a reading nobody made.
    if not isinstance(analysis, str) or not analysis.strip():
        return []
    if analysis.startswith("AI analysis skipped"):
        return []
    return ["## AI Analysis", "", analysis.strip(), "", "---", ""]


def _render_web_exploitation(session: PentestSession) -> list[str]:
    """What the web phase touched, and what it could not answer for.

    The counts reached the JSON export and stopped there, so the page a human
    opens said nothing about the HTTP surface at all -- not even that it had
    been walked. A parameter left untested is a job for someone, and a number
    is not an address.
    """
    kb = getattr(session, "kb", None)
    report = kb.get("exploit.web") if kb is not None else None
    if not isinstance(report, dict):
        # No web phase ran, or the key holds something this cannot read. Either
        # way the section would assert a walk that did not happen.
        return []
    unauthorized = report.get("unauthorized_params")
    inert = report.get("inert_params")
    destructive = report.get("destructive_endpoints")
    phantom = report.get("phantom_endpoints")
    # Validated here rather than in the renderer below, because the heading
    # counts these before anything is rendered: a string would arrive as its
    # own length and report five untested parameters that do not exist.
    unauthorized = unauthorized if isinstance(unauthorized, list) else []
    inert = inert if isinstance(inert, list) else []
    destructive = destructive if isinstance(destructive, list) else []
    phantom = phantom if isinstance(phantom, list) else []
    tested = report.get("endpoints_tested", 0)
    if not (tested or unauthorized or inert or destructive or phantom):
        return []

    sent = report.get("requests_sent", 0)
    confirmed = report.get("confirmed", 0)
    lines = [
        "## Web Exploitation",
        "",
        f"Endpoints tested: {tested} | Requests sent: {sent} | Confirmed: {confirmed}",
        "",
    ]
    if unauthorized:
        lines += [
            f"### Not reached ({len(unauthorized)})",
            "",
            "The target refused these rather than answering them. They were not "
            "tested; reporting them as clean would claim a check that never happened.",
            "",
        ]
        lines += _param_lines(unauthorized) + [""]
    if inert:
        lines += [
            f"### Value not read ({len(inert)})",
            "",
            "Every payload of the first class drew an identical response, so the "
            "value is not reaching anything. A blind vector looks the same from "
            "here; these are the candidates for an out-of-band re-check.",
            "",
        ]
        lines += _param_lines(inert) + [""]
    if destructive:
        lines += [
            f"### Skipped as state-changing ({len(destructive)})",
            "",
            "Left alone because the verb changes state on the target. This is "
            "not evidence of anything: they were never tested. Re-run with "
            "--allow-destructive to include them.",
            "",
        ]
        lines += _endpoint_lines(destructive) + [""]
    if phantom:
        lines += [
            f"### Not routed ({len(phantom)})",
            "",
            "These answered with the page the target returns for any path at "
            "all, so the route does not exist. Nothing was tested here: "
            "calling them clean, or calling their parameters unread, would "
            "claim a check the request never reached.",
            "",
        ]
        lines += _endpoint_lines(phantom) + [""]
    return lines + ["---", ""]


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

    lines += _render_web_exploitation(session)
    # After the surface section: the analysis reads what those sections
    # list, so it follows them rather than opening the report.
    lines += _render_ai_analysis(session)

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
