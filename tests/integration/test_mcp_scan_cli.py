"""CLI surface of `cyberai mcp-scan`: report rendering and MST flags."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyberai.__main__ import cli


def _result() -> dict:
    return {
        "endpoint": "http://t/mcp",
        "transport": "http",
        "connected": True,
        "tools": 2,
        "prompts": 0,
        "resources": 0,
        "error": None,
        "probe": {
            "server_name": "t",
            "server_version": "1.0",
            "tools": [{"name": "read_env", "description": "reads env"}],
        },
        "poisoning": {"suspicious": 1, "tools": [{"tool_name": "read_env", "severity": "HIGH"}]},
        "overprivilege": {"overprivileged": 0, "tools": []},
        "exposure": {"exposed": True, "scan": {"severity": "HIGH"}},
        "attestation": {"unauthenticated": True, "scan": {"severity": "HIGH"}},
        "trust": {"shadowing": 0, "tools": []},
    }


def _run(args: list[str]):
    fake = MagicMock()
    fake.run.return_value = _result()
    with (
        patch("cyberai.cli.mcp_scan.CyberAIConfig"),
        patch("cyberai.cli.mcp_scan.ScanSession"),
        patch("cyberai.cli.mcp_scan.LLMClient"),
        patch("cyberai.cli.mcp_scan.AuditLogger"),
        patch("cyberai.cli.mcp_scan.MCPScanAgent", return_value=fake),
    ):
        result = CliRunner().invoke(cli, ["mcp-scan", *args])
    return result, fake


def test_report_flag_renders_markdown():
    res, _ = _run(["http://t/mcp", "--report"])
    assert res.exit_code == 0, res.output
    assert "MCP Red-Team Report" in res.output
    assert "OWASP MCP Top 10" in res.output


def test_report_json_flag_emits_structured():
    res, _ = _run(["http://t/mcp", "--report-json"])
    assert res.exit_code == 0, res.output
    assert '"owasp_categories"' in res.output
    assert "MCP03:2025" in res.output


def test_mst_and_confirm_scope_pass_context():
    res, fake = _run(["http://t/mcp", "--mst", "--confirm-scope"])
    assert res.exit_code == 0, res.output
    fake.run.assert_called_once()
    ctx = fake.run.call_args.kwargs["context"]
    assert ctx["mst_fuzz"] is True
    assert ctx["confirm_scope"] is True


def test_no_flags_passes_none_context_and_prints_inventory():
    res, fake = _run(["http://t/mcp"])
    assert res.exit_code == 0, res.output
    assert "MCP scan" in res.output
    assert fake.run.call_args.kwargs["context"] is None


def test_transport_flag_passes_context():
    res, fake = _run(["stdio://python3 s.py", "--transport", "stdio"])
    assert res.exit_code == 0, res.output
    assert fake.run.call_args.kwargs["context"] == {"transport": "stdio"}


def test_json_flag_emits_raw_inventory():
    res, _ = _run(["http://t/mcp", "--json"])
    assert res.exit_code == 0, res.output
    assert '"connected"' in res.output


def test_error_result_reports_error():
    fake = MagicMock()
    result = _result()
    result["connected"] = False
    result["error"] = "connection refused"
    fake.run.return_value = result
    with (
        patch("cyberai.cli.mcp_scan.CyberAIConfig"),
        patch("cyberai.cli.mcp_scan.ScanSession"),
        patch("cyberai.cli.mcp_scan.LLMClient"),
        patch("cyberai.cli.mcp_scan.AuditLogger"),
        patch("cyberai.cli.mcp_scan.MCPScanAgent", return_value=fake),
    ):
        res = CliRunner().invoke(cli, ["mcp-scan", "http://t/mcp"])
    assert res.exit_code == 0, res.output
    assert "connection refused" in res.output
