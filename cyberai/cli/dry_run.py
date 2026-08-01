"""
--dry-run mode: show execution plan without running anything.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cyberai.core.safety import ScopeConfig
from cyberai.cli.scope import format_scope

console = Console()


# Full dotted paths: the phase name is not always the package name (the
# "plan" phase lives in cyberai.agents.planner). Enforced by
# tests/unit/test_dry_run_plan.py.
PHASE_TOOLS: dict[str, tuple[str, tuple[str, ...]]] = {
    "recon": (
        "ReconAgent",
        (
            "cyberai.agents.recon.nmap_tool",
            "cyberai.agents.recon.dns_tool",
            "cyberai.agents.recon.subdomain_enum",
            "cyberai.agents.recon.web_surface",
            "cyberai.agents.recon.llm_detector",
            "cyberai.agents.recon.behavioral",
        ),
    ),
    "intel": (
        "IntelAgent",
        (
            "cyberai.agents.intel.nvd_client",
            "cyberai.agents.intel.epss_client",
            "cyberai.agents.intel.service_mapper",
            "cyberai.agents.intel.version_match",
            "cyberai.agents.intel.risk_prioritizer",
        ),
    ),
    "plan": (
        "PlannerAgent",
        (
            "cyberai.agents.planner.agent",
            "cyberai.agents.planner.critic",
        ),
    ),
    "exploit": (
        "ExploitAgent",
        (
            "cyberai.agents.exploit.chain_builder",
            "cyberai.agents.exploit.attack_path",
            "cyberai.agents.exploit.cvss_analyzer",
            "cyberai.agents.exploit.poc_mapper",
            "cyberai.agents.exploit.nuclei_engine",
            "cyberai.agents.exploit.web_exploit",
        ),
    ),
    "report": (
        "ReportAgent",
        (
            "cyberai.agents.report.markdown_renderer",
            "cyberai.agents.report.html_renderer",
            "cyberai.agents.report.json_exporter",
            "cyberai.agents.report.judge",
        ),
    ),
}


def show_dry_run_plan(
    target: str,
    scope: ScopeConfig,
    output_path: str,
    phases: list[str] | None = None,
):
    """
    Print what CyberAI WOULD do, without executing.
    Used when --dry-run flag is passed.
    """
    if phases is None:
        phases = ["recon", "intel", "exploit", "report"]

    console.print(
        Panel.fit(
            "[bold yellow]DRY RUN — no actions will be executed[/bold yellow]",
            border_style="yellow",
        )
    )

    console.print(f"\n[bold]Target:[/bold]  [cyan]{target}[/cyan]")
    console.print(f"[bold]Scope:[/bold]   [dim]{format_scope(scope)}[/dim]")
    console.print(f"[bold]Output:[/bold]  [dim]{output_path}[/dim]")
    console.print(
        f"[bold]Auth:[/bold]    {'[green]authorized[/green]' if scope.authorized else '[red]NOT authorized[/red]'}"
    )

    table = Table(title="\nExecution Plan", border_style="dim")
    table.add_column("Phase", style="cyan", no_wrap=True)
    table.add_column("Agent", style="white")
    table.add_column("Tools", style="dim")

    for i, phase in enumerate(phases, 1):
        agent, modules = PHASE_TOOLS.get(phase, (phase, ()))
        table.add_row(
            f"{i}. {phase}", agent, " · ".join(m.rsplit(".", 1)[-1] for m in modules) or "—"
        )

    console.print(table)
    console.print("\n[dim]Run without --dry-run to execute.[/dim]\n")
