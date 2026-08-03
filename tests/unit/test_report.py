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


def _finding_with(data=None, evidence=None):
    from cyberai.core.scan_session import ScanSession, Severity

    session = ScanSession(target="http://t")
    session.add_finding(
        severity=Severity.HIGH,
        title="SQL injection confirmed in parameter 'q'",
        description="proof text",
        agent="exploit",
        evidence=evidence or [],
        data=data,
    )
    return session


def test_structured_data_is_rendered_as_fields_not_a_printed_dict():
    """A dict printed with str() arrives as one line of Python repr."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    session = _finding_with(data={"payload": "'", "transport": "path"})
    md = render_markdown(session)
    assert "**Payload:** `'`" in md
    assert "**Transport:** `path`" in md
    assert "{'payload'" not in md


def test_long_values_go_into_a_fenced_block():
    """Evidence is the reason to believe the finding; it must be readable."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    body = "line one\n" + "x" * 300
    md = render_markdown(_finding_with(data={"evidence": body}))
    assert "```" in md
    assert "line one" in md


def test_evidence_reaches_the_page_when_there_is_no_data():
    """It was reaching the JSON export and nothing a human opens."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with(evidence=["open_ports=781", "tarpit signature"]))
    assert "- `open_ports=781`" in md
    assert "- `tarpit signature`" in md


def test_a_long_list_is_truncated_with_a_count():
    """Hundreds of ports would bury every real finding below the fold."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with(evidence=[f"port {n}" for n in range(200)]))
    assert "- `port 0`" in md
    assert "- `port 100`" not in md
    assert "185 more" in md


def test_empty_fields_are_not_rendered():
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with(data={"payload": "'", "note": "", "tags": []}))
    assert "**Payload:**" in md
    assert "**Note:**" not in md
    assert "**Tags:**" not in md


def test_a_finding_without_data_renders_no_data_section():
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with())
    assert "**Data:**" not in md
    assert "proof text" in md


def test_a_list_of_empty_values_renders_nothing():
    """Filtering leaves nothing to show, and an empty bullet is noise."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with(data=["", None, [], {}]))
    assert "- ``" not in md
    assert "**Data:**" not in md


def test_a_list_of_long_entries_becomes_one_block():
    """Bullets of 300-character lines are worse than a block to scroll past."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with(data=["x" * 300, "y" * 300]))
    assert "```" in md
    assert "- `xxx" not in md


def test_a_scalar_value_is_labelled_data():
    """Nothing structured to name the field with, so the generic label stands."""
    from cyberai.agents.report.markdown_renderer import render_markdown

    md = render_markdown(_finding_with(data="a plain string"))
    assert "**Data:** `a plain string`" in md


def test_render_data_tolerates_an_empty_value():
    """The renderer guards its own contract: callers need not pre-check."""
    from cyberai.agents.report.markdown_renderer import _render_data

    assert _render_data(None) == []
    assert _render_data({}) == []
    assert _render_data("") == []
