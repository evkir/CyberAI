"""
CyberAI CLI — main scan command.
"""
import click
from pathlib import Path
from cyberai.cli.progress import print_banner, phase_spinner, print_result_summary
from cyberai.cli.scope import parse_scope
from cyberai.cli.dry_run import show_dry_run_plan


@click.group()
def cli():
    """CyberAI — AI-native pentest platform."""
    pass


@cli.command()
@click.argument("target")
@click.option(
    "--scope", "-s",
    default=None,
    help="Authorized scope: IPs, CIDRs, domains (comma-separated). E.g. 10.10.10.0/24",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show execution plan without running anything.",
)
@click.option(
    "--output", "-o",
    default="reports/",
    show_default=True,
    help="Output directory or file path for the generated report.",
    type=click.Path(),
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
def scan(target: str, scope: str, dry_run: bool, output: str, verbose: bool):
    """
    Run a full recon→intel→exploit→report pipeline against TARGET.

    Examples:\n
      cyberai scan 10.10.10.1 --scope 10.10.10.0/24\n
      cyberai scan target.htb --dry-run\n
      cyberai scan 10.10.10.1 --output ./reports/target.md
    """
    print_banner()

    # Parse scope
    try:
        scope_config = parse_scope(scope or target)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--scope")

    # Resolve output path
    output_path = Path(output)
    if output_path.is_dir() or str(output_path).endswith("/"):
        safe_name = target.replace(".", "_").replace("/", "_")
        output_path = output_path / f"{safe_name}_report.md"

    # Dry run
    if dry_run:
        show_dry_run_plan(target, scope_config, str(output_path))
        return

    # Real execution
    import asyncio
    from cyberai.core.pipeline import AsyncPipeline

    click.echo(f"[*] Target:  {target}")
    click.echo(f"[*] Output:  {output_path}")
    click.echo(f"[*] Scope:   {scope or 'auto'}\n")

    with phase_spinner(f"Running pipeline against {target}..."):
        pipeline = AsyncPipeline()
        result = asyncio.run(pipeline.run(target))

    if result.success:
        print_result_summary({
            "target": target,
            "nmap": result.recon,
            "intel": result.intel,
        })
        click.echo(f"\n[+] Report saved → {output_path}")
    else:
        click.echo(f"\n[-] Pipeline failed: {result.error}", err=True)
        raise SystemExit(1)
