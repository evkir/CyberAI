"""
--dry-run mode: show execution plan without running anything.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cyberai.core.safety import ScopeConfig
from cyberai.cli.scope import format_scope

console = Console()


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

    phase_map = {
        "recon": ("ReconAgent", "nmap · dns · tls"),
        "intel": ("IntelAgent", "nvd_client · cve_scorer · tls_cve_mapper"),
        "exploit": ("ExploitAgent", "ssrf_workflow · xxe_workflow · chain_builder"),
        "report": ("ReportAgent", "markdown_renderer · html_renderer · json_exporter"),
    }

    for i, phase in enumerate(phases, 1):
        agent, tools = phase_map.get(phase, (phase, "—"))
        table.add_row(f"{i}. {phase}", agent, tools)

    console.print(table)
    console.print("\n[dim]Run without --dry-run to execute.[/dim]\n")
