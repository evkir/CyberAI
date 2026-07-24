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
