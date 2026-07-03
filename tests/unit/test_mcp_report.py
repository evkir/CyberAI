"""Tests for the MCP red-team report (OWASP MCP Top 10 + MITRE ATLAS mapping)."""

from __future__ import annotations

import json

from cyberai.agents.mcp_scan.report import (
    build_mcp_report,
    build_risk_rows,
    render_mcp_report_json,
)


def _clean_result() -> dict:
    return {
        "endpoint": "stdio://python3 server.py",
        "transport": "stdio",
        "connected": True,
        "tools": 0,
        "error": None,
        "poisoning": {"suspicious": 0, "tools": []},
        "overprivilege": {"overprivileged": 0, "tools": []},
        "exposure": {"exposed": False, "scan": {}},
        "attestation": {"unauthenticated": False, "scan": {}},
        "trust": {"shadowing": 0, "tools": []},
    }


def _rich_result() -> dict:
    return {
        "endpoint": "http://evil.example.com/mcp",
        "transport": "http",
        "connected": True,
        "tools": 3,
        "error": None,
        "poisoning": {"suspicious": 1, "tools": [{"tool_name": "read_env", "severity": "HIGH"}]},
        "overprivilege": {
            "overprivileged": 1,
            "tools": [{"tool_name": "exec", "severity": "CRITICAL"}],
        },
        "exposure": {
            "exposed": True,
            "scan": {"severity": "HIGH", "dangerous_capabilities": ["exec"]},
        },
        "attestation": {"unauthenticated": True, "scan": {"severity": "HIGH"}},
        "trust": {"shadowing": 1, "tools": [{"tool_name": "hook", "severity": "MEDIUM"}]},
    }


def test_build_risk_rows_five_stages_without_mst():
    rows = build_risk_rows(_clean_result())
    assert [r.stage for r in rows] == [
        "tool-poisoning",
        "over-privilege",
        "trust-propagation",
        "attestation",
        "exposure",
    ]
    # clean result -> no signals anywhere
    assert all(r.signals == 0 for r in rows)


def test_owasp_and_atlas_ids_are_canonical():
    rows = {r.stage: r for r in build_risk_rows(_rich_result())}
    assert rows["tool-poisoning"].owasp_id == "MCP03:2025"
    assert rows["tool-poisoning"].atlas_id == "AML.T0110"
    assert rows["over-privilege"].owasp_id == "MCP02:2025"
    assert rows["over-privilege"].atlas_id == "AML.T0086"
    assert rows["trust-propagation"].owasp_id == "MCP06:2025"
    assert rows["trust-propagation"].atlas_id == "AML.T0051"
    assert rows["attestation"].owasp_id == "MCP07:2025"
    assert rows["exposure"].owasp_id == "MCP07:2025"
    assert rows["exposure"].atlas_id == "AML.T0040"


def test_mst_row_only_when_present():
    assert all(r.stage != "mst-fuzzing" for r in build_risk_rows(_rich_result()))
    res = _rich_result()
    res["mst"] = [{"check": "stdio_rce", "severity": "CRITICAL", "detail": "rce"}]
    rows = build_risk_rows(res)
    mst = [r for r in rows if r.stage == "mst-fuzzing"]
    assert len(mst) == 1
    assert mst[0].owasp_id == "MCP05:2025"
    assert mst[0].severity == "CRITICAL"
    assert mst[0].tools == ["stdio_rce"]


def test_row_severity_is_worst_of_stage():
    res = _rich_result()
    res["poisoning"]["tools"] = [
        {"tool_name": "a", "severity": "LOW"},
        {"tool_name": "b", "severity": "CRITICAL"},
        {"tool_name": "c", "severity": "MEDIUM"},
    ]
    res["poisoning"]["suspicious"] = 3
    row = {r.stage: r for r in build_risk_rows(res)}["tool-poisoning"]
    assert row.severity == "CRITICAL"
    assert row.signals == 3
    assert row.tools == ["a", "b", "c"]


def test_report_clean_has_no_hits():
    md, data = build_mcp_report(_clean_result())
    assert data["owasp_categories"] == []
    assert data["atlas_techniques"] == []
    assert data["severity_summary"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    assert "# MCP Red-Team Report" in md
    assert "STRIDE" in md  # scorecard embedded


def test_report_rich_mapping_and_summary():
    res = _rich_result()
    res["mst"] = [{"check": "stdio_rce", "severity": "CRITICAL", "detail": "rce"}]
    md, data = build_mcp_report(res)
    assert data["owasp_categories"] == [
        "MCP02:2025",
        "MCP03:2025",
        "MCP05:2025",
        "MCP06:2025",
        "MCP07:2025",
    ]
    assert data["atlas_techniques"] == ["AML.T0040", "AML.T0051", "AML.T0086", "AML.T0110"]
    assert data["severity_summary"]["CRITICAL"] == 2  # exec + stdio_rce
    assert (
        data["severity_summary"]["HIGH"] == 3
    )  # poisoning + attestation + exposure (trust is MEDIUM)
    # flagged items section lists tool names
    assert "read_env" in md and "exec" in md and "hook" in md
    # MCP06 beta-drift note present
    assert "Prompt Injection via Contextual Payloads" in md


def test_render_json_roundtrip():
    payload = render_mcp_report_json(_rich_result())
    data = json.loads(payload)
    assert data["endpoint"] == "http://evil.example.com/mcp"
    assert data["transport"] == "http"
    assert isinstance(data["risks"], list) and len(data["risks"]) == 5
