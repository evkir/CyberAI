import pytest
from datetime import datetime, timezone
from cyberai.core.session import PentestSession, Finding, Severity
from cyberai.agents.report.markdown_renderer import render_markdown


def make_finding(title, severity, agent="test", cve=None):
    return Finding(
        id=1,
        severity=severity,
        title=title,
        description=f"Test description for {title}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent=agent,
        cve=cve,
    )


def make_session():
    s = PentestSession(target="testhost.local")
    s.findings.append(make_finding("Open SSH Port", Severity.INFO))
    s.findings.append(make_finding("Log4Shell", Severity.CRITICAL, cve="CVE-2021-44228"))
    return s


def test_render_markdown_contains_target():
    s = make_session()
    md = render_markdown(s)
    assert "testhost.local" in md


def test_render_markdown_contains_findings():
    s = make_session()
    md = render_markdown(s)
    assert "Log4Shell" in md


def test_render_markdown_severity_counts():
    s = make_session()
    md = render_markdown(s)
    # At least one critical and one info finding present
    assert "CRITICAL" in md or "Critical" in md
    assert "INFO" in md or "Info" in md


def test_render_markdown_has_summary_table():
    s = make_session()
    md = render_markdown(s)
    assert "testhost.local" in md
    assert len(md) > 100
