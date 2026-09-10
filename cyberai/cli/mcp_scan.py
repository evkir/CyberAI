"""`cyberai mcp-scan` — inventory and red-team a target MCP server or LLM endpoint.

Offensive read side: connect to a target MCP endpoint, inventory its advertised
capability surface (tools, prompts, resources), run the static red-team analyses,
and optionally emit an OWASP-MCP / MITRE-ATLAS red-team report. With ``--mst`` the
optional low-level MST fuzzer runs too (see ``--confirm-scope`` for non-lab
targets). ENDPOINT is a stdio command line, an http(s):// URL (streamable-HTTP),
or an sse:// URL.
"""

from __future__ import annotations

import json
from typing import Any

import click
from rich.console import Console

from cyberai.agents.mcp_scan import MCPScanAgent
from cyberai.agents.mcp_scan.report import build_mcp_report, render_mcp_report_json
from cyberai.core.config import CyberAIConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.logger import AuditLogger
from cyberai.core.scan_session import ScanSession

console = Console()


def _tri(value: object) -> str:
    """Three-state rendering: a key absent from metadata is not a refusal."""
    return "n/a" if value is None else ("yes" if value else "no")


def _auth_line(result: dict[str, Any]) -> str | None:
    """One line of published authorization posture, or None where it cannot apply."""
    auth = result.get("auth_metadata") or {}
    if not auth.get("applicable"):
        return None
    return (
        f"  auth: PRM {'yes' if auth['prm_present'] else 'no'} "
        f"(via {auth['prm_source']})  DCR {_tri(auth['dcr_offered'])}  "
        f"CIMD {_tri(auth['cimd_supported'])}  "
        f"iss {_tri(auth['iss_parameter_advertised'])}"
    )


@click.command("mcp-scan")
@click.argument("endpoint")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "http"]),
    default=None,
    help="Force transport instead of inferring it from ENDPOINT",
)
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON inventory")
@click.option(
    "--report",
    "as_report",
    is_flag=True,
    help="Emit an OWASP-MCP / MITRE-ATLAS red-team report (Markdown)",
)
@click.option(
    "--report-json",
    "as_report_json",
    is_flag=True,
    help="Emit the structured red-team report as JSON",
)
@click.option(
    "--mst",
    "use_mst",
    is_flag=True,
    help="Also run the optional MST low-level fuzzer (requires mas-sentry)",
)
@click.option(
    "--confirm-scope",
    is_flag=True,
    help="Confirm authorization to fuzz a non-lab target with --mst",
)
def mcp_scan(
    endpoint: str,
    transport: str | None,
    as_json: bool,
    as_report: bool,
    as_report_json: bool,
    use_mst: bool,
    confirm_scope: bool,
) -> None:
    """Inventory and red-team a target MCP server or LLM ENDPOINT."""
    config = CyberAIConfig.from_env()
    session = ScanSession(target=endpoint)
    llm = LLMClient(config.llm)
    audit = AuditLogger(session.session_id, output_dir=config.output_dir)
    agent = MCPScanAgent(config, session, llm, audit)

    context: dict[str, object] = {}
    if transport:
        context["transport"] = transport
    if use_mst:
        context["mst_fuzz"] = True
    if confirm_scope:
        context["confirm_scope"] = True

    result = agent.run(endpoint, context=context or None)

    if as_json:
        console.print_json(json.dumps(result))
        return
    if as_report_json:
        click.echo(render_mcp_report_json(result))
        return
    if as_report:
        markdown, _ = build_mcp_report(result)
        click.echo(markdown)
        return

    status = "[green]connected[/green]" if result["connected"] else "[red]failed[/red]"
    console.print(f"[bold]MCP scan[/bold] {endpoint} ({result['transport']}) — {status}")
    # The posture is a property of the endpoint, not of the session: a server
    # that refuses an anonymous session is exactly the one whose published
    # metadata is the only thing left to measure. Printed before the exit.
    line = _auth_line(result)
    if line:
        console.print(line, highlight=False)
    if result["error"]:
        console.print(f"[red]error:[/red] {result['error']}")
        return
    console.print(
        f"  server: {result['probe']['server_name']} v{result['probe']['server_version']}"
    )
    # highlight=False: rich colourises digit runs, which splits the revision
    # into escape-separated fragments and makes the line ungreppable.
    console.print(f"  revision: {result['probe']['protocol_version']}", highlight=False)
    console.print(
        f"  tools: {result['tools']}  prompts: {result['prompts']}  "
        f"resources: {result['resources']}"
    )
    for tool in result["probe"]["tools"]:
        console.print(f"    [cyan]{tool['name']}[/cyan] — {tool.get('description', '')}")

    # The analyses ran either way; until now only --report and --report-json
    # could see them, so the default exit inventoried the surface and threw
    # every finding away. Same producer as the report, no second renderer.
    _, report = build_mcp_report(result)
    summary = report["severity_summary"]
    console.print(
        "  risks: " + "  ".join(f"{level} {count}" for level, count in summary.items()),
        highlight=False,
    )
    flagged = [row for row in report["risks"] if row["signals"] > 0]
    if not flagged:
        console.print("  no stage raised a signal", highlight=False)
        return
    for row in flagged:
        named = ", ".join(row["tools"]) or "the endpoint itself"
        console.print(
            f"    {row['stage']} — {row['severity']} — {row['owasp_id']} — {named}",
            highlight=False,
        )
