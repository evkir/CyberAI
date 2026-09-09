"""CLI surface of `cyberai mcp-scan`: report rendering and MST flags."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.mcp.auth_metadata import AuthMetadata
from cyberai.mcp.client_probe import MCPProbeResult

REVISION = "2025-11-25"


def _auth(**overrides: object) -> dict:
    """Authorization posture in the shape the probe produces, as measured live."""
    metadata = AuthMetadata(
        endpoint="http://t/mcp",
        challenged=True,
        resource_metadata_url="http://t/.well-known/oauth-protected-resource/mcp",
        prm_source="header",
        prm_present=True,
        resource="http://t/mcp",
        authorization_servers=["http://t"],
        issuer="http://t",
        dcr_offered=True,
        cimd_supported=True,
    )
    for key, value in overrides.items():
        setattr(metadata, key, value)
    return metadata.to_dict()


def _probe() -> dict:
    """Build the probe payload from the producer, not by hand.

    A hand-written dict is a snapshot of what the probe returned on the day
    the test was written. When the probe grew protocol_version the CLI read a
    key three tests had never heard of, and they failed on a shape production
    never sends. Serializing the real dataclass keeps the fake in step with
    the field list by construction.
    """
    return MCPProbeResult(
        endpoint="http://t/mcp",
        transport="http",
        connected=True,
        server_name="t",
        server_version="1.0",
        protocol_version=REVISION,
        tools=[{"name": "read_env", "description": "reads env"}],
    ).to_dict()


def _result() -> dict:
    return {
        "endpoint": "http://t/mcp",
        "transport": "http",
        "connected": True,
        "protocol_version": REVISION,
        "tools": 2,
        "prompts": 0,
        "resources": 0,
        "error": None,
        "probe": _probe(),
        "auth_metadata": _auth(),
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


def test_a_refused_session_still_reports_the_published_posture():
    """The endpoint that rejects an anonymous session is the interesting one.

    Its metadata is published for unauthenticated clients, so it is readable
    exactly when the session is not. Printing the posture after the error exit
    would have hidden it on every closed server -- which is all of them.
    """
    with patch("cyberai.cli.mcp_scan.MCPScanAgent") as agent:
        agent.return_value.run.return_value = {
            **_result(),
            "connected": False,
            "error": "ExceptionGroup: unhandled errors in a TaskGroup",
        }
        with (
            patch("cyberai.cli.mcp_scan.CyberAIConfig"),
            patch("cyberai.cli.mcp_scan.ScanSession"),
            patch("cyberai.cli.mcp_scan.LLMClient"),
            patch("cyberai.cli.mcp_scan.AuditLogger"),
        ):
            res = CliRunner().invoke(cli, ["mcp-scan", "http://t/mcp"])

    assert res.exit_code == 0, res.output
    assert "auth: PRM yes" in res.output
    assert "error:" in res.output


def test_a_stdio_target_gets_no_authorization_line_at_all():
    """stdio has no network origin; a posture line there would be invented."""
    with patch("cyberai.cli.mcp_scan.MCPScanAgent") as agent:
        agent.return_value.run.return_value = {
            **_result(),
            "transport": "stdio",
            "auth_metadata": _auth(applicable=False),
        }
        with (
            patch("cyberai.cli.mcp_scan.CyberAIConfig"),
            patch("cyberai.cli.mcp_scan.ScanSession"),
            patch("cyberai.cli.mcp_scan.LLMClient"),
            patch("cyberai.cli.mcp_scan.AuditLogger"),
        ):
            res = CliRunner().invoke(cli, ["mcp-scan", "python3 s.py"])

    assert res.exit_code == 0, res.output
    assert "auth:" not in res.output


def test_the_report_names_the_posture_and_its_pointer():
    res, _ = _run(["http://t/mcp", "--report"])

    assert res.exit_code == 0, res.output
    assert "## Authorization metadata" in res.output
    assert "- metadata pointer: header" in res.output
    assert "- iss in authorization response: not advertised" in res.output
