"""CyberAI CLI — entry point for the pentest pipeline."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

from .core.config import CyberAIConfig
from .core.orchestrator import Orchestrator

console = Console()

BANNER = """
[bold red]
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
[/bold red]
[dim]AI-native pentest platform[/dim]
"""


@click.group()
def cli() -> None:
    """CyberAI — AI-powered pentest platform."""


@cli.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--provider", default=None, help="LLM provider (openai/anthropic/ollama)")
@click.option("--dry-run", is_flag=True, help="Run pipeline without real network calls")
@click.option("--scope", multiple=True, help="Authorized scope entry (repeatable)")
def scan(
    target: str,
    verbose: bool,
    provider: str | None,
    dry_run: bool,
    scope: tuple[str, ...],
) -> None:
    """Run full pentest pipeline against TARGET."""
    console.print(BANNER)
    console.print(Panel(f"[bold]Target:[/bold] {target}", style="red"))

    config = CyberAIConfig.from_env()
    config.verbose = verbose
    if provider:
        config.llm.provider = provider

    orchestrator = Orchestrator(config=config, dry_run=dry_run)

    console.print("[yellow]→[/yellow] Starting pipeline...")
    session = orchestrator.run(target, authorized_scope=list(scope))

    console.print(f"\n[green]✓[/green] Done. Findings: {len(session.findings)}")
    summary = session.summary()
    for key, value in summary.items():
        console.print(f"  {key}: {value}")


@cli.command()
def status() -> None:
    """Show CyberAI status and config."""
    config = CyberAIConfig.from_env()
    console.print(
        Panel(
            f"Provider: {config.llm.provider}\n"
            f"Model: {config.llm.model}\n"
            f"Output: {config.output_dir}",
            title="CyberAI Status",
        )
    )


if __name__ == "__main__":
    cli()
