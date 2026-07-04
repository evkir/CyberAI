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

import click
from rich.console import Console

from cyberai.agents.mcp_scan import MCPScanAgent
from cyberai.agents.mcp_scan.report import build_mcp_report, render_mcp_report_json
from cyberai.core.config import CyberAIConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.logger import AuditLogger
from cyberai.core.scan_session import ScanSession

console = Console()


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
    if result["error"]:
        console.print(f"[red]error:[/red] {result['error']}")
        return
    console.print(
        f"  server: {result['probe']['server_name']} v{result['probe']['server_version']}"
    )
    console.print(
        f"  tools: {result['tools']}  prompts: {result['prompts']}  "
        f"resources: {result['resources']}"
    )
    for tool in result["probe"]["tools"]:
        console.print(f"    [cyan]{tool['name']}[/cyan] — {tool.get('description', '')}")
