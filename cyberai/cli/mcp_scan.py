"""`cyberai mcp-scan` — inventory a target MCP server or LLM endpoint.

This is the offensive read side: connect to a target MCP endpoint and print the
advertised capability surface (tools, prompts, resources). At this stage the
command only inventories; metadata analysis and live injection land in later
commits. ENDPOINT is a stdio command line, an http(s):// URL (streamable-HTTP),
or an sse:// URL.
"""

from __future__ import annotations

import json

import click
from rich.console import Console

from cyberai.agents.mcp_scan import MCPScanAgent
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
def mcp_scan(endpoint: str, transport: str | None, as_json: bool) -> None:
    """Inventory a target MCP server or LLM ENDPOINT."""
    config = CyberAIConfig.from_env()
    session = ScanSession(target=endpoint)
    llm = LLMClient(config.llm)
    audit = AuditLogger(session.session_id, output_dir=config.output_dir)
    agent = MCPScanAgent(config, session, llm, audit)

    result = agent.run(endpoint, context={"transport": transport} if transport else None)

    if as_json:
        console.print_json(json.dumps(result))
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
