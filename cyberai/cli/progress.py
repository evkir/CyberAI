"""
Progress bars and spinners for CLI operations.
Uses rich for clean terminal output.
"""

from contextlib import contextmanager
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)

console = Console()


@contextmanager
def pipeline_progress():
    """
    Context manager: shows progress bar across all pipeline phases.

    Usage:
        with pipeline_progress() as progress:
            task = progress.add_task("Recon...", total=3)
            progress.advance(task)
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[dim]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        yield progress


@contextmanager
def phase_spinner(message: str):
    """
    Simple spinner for a single phase.

    Usage:
        with phase_spinner("Running nmap..."):
            run_nmap(target)
    """
    with console.status(
        f"[bold cyan]{message}",
        spinner="dots",
    ):
        yield


def print_banner():
    console.print("""
[bold cyan]
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
[/bold cyan]
[dim]AI-native pentest platform[/dim]
""")


def print_result_summary(result: dict):
    """Print a clean summary of pipeline results."""
    target = result.get("target", "unknown")
    console.print(f"\n[bold green]✓ Scan complete[/bold green] — [cyan]{target}[/cyan]")

    if ports := result.get("nmap", {}).get("ports", []):
        console.print(f"  [dim]Ports:[/dim] {', '.join(str(p) for p in ports[:10])}")

    if cves := result.get("intel", {}).get("cves", []):
        console.print(f"  [dim]CVEs:[/dim]  {', '.join(cves[:5])}")
