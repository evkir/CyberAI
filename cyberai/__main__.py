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

    from cyberai.cli.replay import save_session

    saved = save_session(session, config.output_dir)
    console.print(f"\n[green]✓[/green] Done. Findings: {len(session.findings)}")
    console.print(
        f"[dim]Session saved: {saved} (replay with: cyberai replay {session.session_id})[/dim]"
    )

    from cyberai.core.cost_tracker import format_summary

    console.print(f"[dim]{format_summary(orchestrator.cost_tracker)}[/dim]")

    summary = session.summary()
    for key, value in summary.items():
        console.print(f"  {key}: {value}")


@cli.command()
@click.argument("session_id")
def replay(session_id: str) -> None:
    """Reload SESSION_ID, re-run in dry-run mode and diff the phases."""
    from cyberai.cli.replay import run_replay

    config = CyberAIConfig.from_env()
    raise SystemExit(run_replay(session_id, config))


@cli.group()
def scope() -> None:
    """Import and inspect bug-bounty program scopes."""


@scope.command("import")
@click.argument("platform", type=click.Choice(["h1", "hackerone", "bugcrowd", "bc"]))
@click.argument("scope_file", type=click.Path(exists=True))
def scope_import(platform: str, scope_file: str) -> None:
    """Import authorized scope from a PLATFORM SCOPE_FILE (JSON export).

    Examples:
        cyberai scope import h1 acme_scope.json
        cyberai scope import bugcrowd acme_bc.json
    """
    from cyberai.cli.scope import import_bugcrowd_scope, import_h1_scope

    if platform in ("bugcrowd", "bc"):
        result = import_bugcrowd_scope(scope_file)
    else:
        result = import_h1_scope(scope_file)
    console.print(
        Panel(
            "\n".join(result.in_scope) or "[dim]none[/dim]",
            title=f"In scope ({len(result.in_scope)})",
            style="green",
        )
    )
    if result.out_of_scope:
        console.print(
            Panel(
                "\n".join(result.out_of_scope),
                title=f"Out of scope ({len(result.out_of_scope)})",
                style="red",
            )
        )
    console.print(f"[dim]{result.summary()}[/dim]")
    console.print(
        "[dim]Use with: cyberai scan <target> "
        + " ".join(f"--scope {s}" for s in result.in_scope[:3])
        + (" ..." if len(result.in_scope) > 3 else "")
        + "[/dim]"
    )


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
