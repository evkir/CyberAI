"""Markdown report groups findings by domain only when a scan spans several."""

from __future__ import annotations

import pathlib

from cyberai.agents.report.json_exporter import export_json, export_summary
from cyberai.agents.report.markdown_renderer import render_markdown
from cyberai.core.scan_session import ScanSession, Severity


def _session(*agents: str) -> ScanSession:
    session = ScanSession(target="acme.tld")
    for idx, agent in enumerate(agents, 1):
        session.add_finding(
            severity=Severity.HIGH,
            title=f"Issue {idx} from {agent}",
            description="detail",
            agent=agent,
        )
    return session


def test_network_only_report_has_no_domain_headings():
    md = render_markdown(_session("recon", "exploit"))
    assert "### Network" not in md
    assert "\n### 1. " in md and "\n### 2. " in md


def test_multi_domain_report_splits_into_sections():
    md = render_markdown(_session("recon", "mcp_scan", "web3"))
    assert "### Network (1)" in md
    assert "### MCP (1)" in md
    assert "### Web3 (1)" in md
    assert md.index("### Network") < md.index("### MCP") < md.index("### Web3")


def test_multi_domain_findings_are_numbered_continuously():
    md = render_markdown(_session("recon", "mcp_scan", "web3"))
    for n in (1, 2, 3):
        assert f"\n#### {n}. " in md
    assert "\n### 1. " not in md


def test_multi_domain_summary_carries_breakdown():
    md = render_markdown(_session("recon", "mcp_scan"))
    assert "Network: 1 | MCP: 1" in md


def test_single_domain_summary_has_no_breakdown():
    md = render_markdown(_session("recon"))
    assert "Network: 1" not in md


def test_empty_session_still_renders():
    md = render_markdown(_session())
    assert "## Findings" in md and "Total findings: 0" in md


def test_json_export_labels_every_finding_with_a_domain(tmp_path):
    import json

    path = export_json(_session("recon", "mcp_scan", "web3"), str(tmp_path))
    report = json.loads(pathlib.Path(path).read_text())
    domains = [f["domain"] for f in report["findings"]]
    assert domains == ["Network", "MCP", "Web3"]
    assert [f["agent"] for f in report["findings"]] == ["recon", "mcp_scan", "web3"]


def test_json_export_indexes_findings_by_domain(tmp_path):
    import json

    path = export_json(_session("recon", "web3", "web3"), str(tmp_path))
    report = json.loads(pathlib.Path(path).read_text())
    index = report["findings_by_domain"]
    assert list(index) == ["Network", "Web3"]
    assert len(index["Web3"]) == 2


def test_json_export_of_single_domain_has_one_bucket(tmp_path):
    import json

    path = export_json(_session("recon"), str(tmp_path))
    report = json.loads(pathlib.Path(path).read_text())
    assert list(report["findings_by_domain"]) == ["Network"]


def test_summary_carries_domain_buckets():
    summary = export_summary(_session("recon", "mcp_scan"))
    assert list(summary["findings_by_domain"]) == ["Network", "MCP"]
    assert summary["findings_by_domain"]["MCP"][0]["title"].endswith("from mcp_scan")


def test_summary_of_empty_session_has_no_domains():
    assert export_summary(_session())["findings_by_domain"] == {}


def test_optional_finding_fields_are_rendered():
    """Confidence, CVE and data blocks only appear when the finding sets them."""
    session = ScanSession(target="acme.tld")
    finding = session.add_finding(
        severity=Severity.CRITICAL,
        title="Blind SSRF confirmed",
        description="callback received",
        agent="exploit",
        cve="CVE-2021-44228",
        data={"token": "abc123"},
    )
    finding.confidence = 0.5

    md = render_markdown(session)
    assert "**Confidence:** 50%" in md
    assert "**CVE:** `CVE-2021-44228`" in md
    assert "abc123" in md


def test_optional_finding_fields_absent_when_unset():
    md = render_markdown(_session("recon"))
    assert "**Confidence:**" not in md
    assert "**CVE:**" not in md
    assert "**Data:**" not in md


def _web_session(report: dict) -> ScanSession:
    session = ScanSession(target="acme.tld")
    session.kb.set("exploit.web", report, agent="exploit")
    return session


def test_web_section_names_the_parameters_it_could_not_reach():
    """A count of ten is not ten addresses.

    The reader who has to finish by hand needs to know which parameter on
    which endpoint went untested, and that never left the JSON export.
    """
    md = render_markdown(
        _web_session(
            {
                "endpoints_tested": 2,
                "requests_sent": 40,
                "confirmed": 0,
                "unauthorized_params": [
                    {
                        "url": "http://acme.tld/rest/user",
                        "parameter": "email",
                        "method": "POST",
                        "transport": "json-body",
                    }
                ],
                "inert_params": [
                    {
                        "url": "http://acme.tld/reviews",
                        "parameter": "id",
                        "method": "GET",
                        "transport": "query",
                    }
                ],
            }
        )
    )
    assert "## Web Exploitation" in md
    assert "### Not reached (1)" in md
    assert "`POST http://acme.tld/rest/user` -- parameter `email` (json-body)" in md
    assert "### Value not read (1)" in md
    assert "`GET http://acme.tld/reviews` -- parameter `id` (query)" in md


def test_a_run_without_a_web_phase_renders_exactly_as_before():
    """The section must not announce itself on a network-only scan."""
    assert "## Web Exploitation" not in render_markdown(_session("recon"))


def test_a_long_parameter_list_is_truncated_rather_than_dumped():
    """Juice Shop returns dozens; a report nobody scrolls is a report nobody reads."""
    md = render_markdown(
        _web_session(
            {
                "endpoints_tested": 1,
                "inert_params": [
                    {
                        "url": f"http://acme.tld/{i}",
                        "parameter": "q",
                        "method": "GET",
                        "transport": "query",
                    }
                    for i in range(20)
                ],
            }
        )
    )
    assert "http://acme.tld/14" in md
    assert "http://acme.tld/15" not in md
    assert "and 5 more" in md


def test_an_unreadable_web_entry_produces_no_section_and_no_crash():
    """A restored snapshot can put anything under that key.

    Rendering a heading over a value nobody could parse claims the HTTP
    surface was walked, which is the lie this section exists to avoid.
    """
    session = ScanSession(target="acme.tld")
    session.kb.set("exploit.web", "endpoints_tested=2", agent="exploit")
    md = render_markdown(session)
    assert "## Web Exploitation" not in md
    assert "endpoints_tested" not in md
