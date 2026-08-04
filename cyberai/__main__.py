"""CyberAI CLI — entry point for the pentest pipeline."""

from __future__ import annotations

import os

import click

from cyberai.version import __version__
from rich.console import Console
from rich.panel import Panel

from .core.config import CyberAIConfig, LLMConfig
from .core.orchestrator import Orchestrator
from .core.scan_session import ScanPhase
from .cli.bench import bench
from .cli.mcp_scan import mcp_scan
from .cli.web3_audit import web3

console = Console()


def _detach_stdin_from_tty() -> None:
    """Point fd 0 at /dev/null so scan subprocesses (nmap runtime
    interaction, whois, etc.) can never leave the controlling terminal in
    a raw/no-echo state. The scan pipeline never reads stdin."""
    try:
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
    except OSError:
        pass


def _plan_summary(plan: object) -> str | None:
    """One-line breakdown of the planner TODO, or None when no plan ran."""
    todo = plan.get("todo") if isinstance(plan, dict) else None
    if not isinstance(todo, list):
        return None
    counts: dict[str, int] = {}
    for task in todo:
        if isinstance(task, dict):
            action = str(task.get("action", "unknown"))
            counts[action] = counts.get(action, 0) + 1
    if not counts:
        return None
    breakdown = ", ".join(f"{n} {a}" for a, n in sorted(counts.items()))
    return f"Plan: {sum(counts.values())} subtask(s) - {breakdown}"


def _apply_feature_overrides(
    config: CyberAIConfig,
    *,
    target: str = "",
    behavioral: bool | None = None,
    nuclei: bool | None = None,
    judge: bool | None = None,
    replan: bool | None = None,
    planner: bool | None = None,
    air_gapped: bool | None = None,
    web_recon: bool | None = None,
    web_exploit: bool | None = None,
    api_discovery: bool | None = None,
    probe_routes: bool | None = None,
    plan_web_order: bool | None = None,
    planned_redteam: bool | None = None,
    native_tools: bool | None = None,
    llm_summary: bool | None = None,
) -> CyberAIConfig:
    """Apply CLI feature-flag overrides onto a config built from the env.

    Each flag is tri-state: None leaves the env/default value untouched,
    True/False forces it. The CLI can thus both enable and disable a flag
    regardless of what the environment set.

    An http(s) target additionally turns the web phase on before the explicit
    flags are read. Scanning a URL with web recon off produces an empty report
    while the surface is sitting right there, and a silent nothing reads like
    a clean target rather than a phase that never ran. Explicit flags still
    win, so --no-web-recon disables it again; the shape of the target only
    decides the default.
    """
    if target.lower().startswith(("http://", "https://")):
        config.use_web_recon = True
        config.use_api_discovery = True
        config.use_web_exploit = True

    if behavioral is not None:
        config.use_behavioral_fingerprint = behavioral
    if nuclei is not None:
        config.use_nuclei = nuclei
    if judge is not None:
        config.use_judge = judge
    if replan is not None:
        config.enable_replan = replan
    if planner is not None:
        config.enable_planner = planner
    if air_gapped is not None:
        config.air_gapped = air_gapped
    if web_recon is not None:
        config.use_web_recon = web_recon
    if web_exploit is not None:
        config.use_web_exploit = web_exploit
    if api_discovery is not None:
        config.use_api_discovery = api_discovery
    if probe_routes is not None:
        config.use_route_probing = probe_routes
    if plan_web_order is not None:
        config.use_plan_web_order = plan_web_order
    if planned_redteam is not None:
        config.use_planned_redteam = planned_redteam
    if native_tools is not None:
        config.use_native_tools = native_tools
    if llm_summary is not None:
        config.use_llm_summary = llm_summary
    return config


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
@click.version_option(__version__, "-V", "--version", prog_name="cyberai")
def cli() -> None:
    """CyberAI — AI-powered pentest platform."""


@cli.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--provider", default=None, help="LLM provider (openai/anthropic/ollama)")
@click.option("--model", default=None, help="LLM model (overrides provider default)")
@click.option("--dry-run", is_flag=True, help="Run pipeline without real network calls")
@click.option("--scope", multiple=True, help="Authorized scope entry (repeatable)")
@click.option(
    "--recon-only", is_flag=True, help="Run only the recon phase (safe for external targets)"
)
@click.option(
    "--max-rps",
    type=int,
    default=None,
    help="Cap nmap scan rate (packets/sec) for external targets",
)
@click.option(
    "--behavioral/--no-behavioral",
    default=None,
    help="Force behavioral fingerprint (honeypot/WAF/tarpit) on or off",
)
@click.option(
    "--nuclei/--no-nuclei", default=None, help="Force the nuclei exploit engine on or off"
)
@click.option(
    "--judge/--no-judge", default=None, help="Force the LLM-as-Judge report check on or off"
)
@click.option(
    "--replan/--no-replan", default=None, help="Force critic-driven phase replan on or off"
)
@click.option(
    "--planner/--no-planner",
    default=None,
    help="Force the graph planner phase before exploit on or off",
)
@click.option(
    "--air-gapped/--no-air-gapped",
    default=None,
    help="Force local-only (no-egress) LLM path on or off",
)
@click.option(
    "--web-recon/--no-web-recon",
    default=None,
    help="Force crawling the target for injectable HTTP endpoints on or off",
)
@click.option(
    "--web-exploit/--no-web-exploit",
    default=None,
    help="Force direct exploitation of the discovered HTTP surface on or off",
)
@click.option(
    "--api-discovery/--no-api-discovery",
    default=None,
    help="Force reading API specs and JS bundles during web recon on or off",
)
@click.option(
    "--probe-routes/--no-probe-routes",
    default=None,
    help="Ask discovered routes whether they read an undeclared parameter",
)
@click.option(
    "--plan-web-order/--no-plan-web-order",
    default=None,
    help="Force attacking the endpoints the planner named first on or off",
)
@click.option(
    "--planned-redteam/--no-planned-redteam",
    default=None,
    help="Force fuzzing the LLM channels the planner named on or off",
)
@click.option(
    "--native-tools/--no-native-tools",
    default=None,
    help="Force letting the model pick and order exploit tools on or off",
)
@click.option(
    "--llm-summary/--no-llm-summary",
    default=None,
    help="Force the LLM-written executive report section on or off",
)
def scan(
    target: str,
    verbose: bool,
    provider: str | None,
    model: str | None,
    dry_run: bool,
    scope: tuple[str, ...],
    recon_only: bool,
    max_rps: int | None,
    behavioral: bool | None,
    nuclei: bool | None,
    judge: bool | None,
    replan: bool | None,
    planner: bool | None,
    air_gapped: bool | None,
    web_recon: bool | None,
    web_exploit: bool | None,
    api_discovery: bool | None,
    probe_routes: bool | None,
    plan_web_order: bool | None,
    planned_redteam: bool | None,
    native_tools: bool | None,
    llm_summary: bool | None,
) -> None:
    """Run full pentest pipeline against TARGET."""
    _detach_stdin_from_tty()
    console.print(BANNER)
    console.print(Panel(f"[bold]Target:[/bold] {target}", style="red"))

    config = CyberAIConfig.from_env()
    # -v forces verbose on; without it, CYBERAI_VERBOSE from the env survives.
    if verbose:
        config.verbose = True
    if provider:
        config.llm.provider = provider
    # --model wins; otherwise a new provider re-resolves its default
    # (unless CYBERAI_MODEL was set explicitly in the environment).
    if model:
        config.llm.model = model
    elif provider and not os.getenv("CYBERAI_MODEL"):
        config.llm.model = LLMConfig.default_model_for(provider)

    _apply_feature_overrides(
        config,
        target=target,
        behavioral=behavioral,
        nuclei=nuclei,
        judge=judge,
        replan=replan,
        planner=planner,
        air_gapped=air_gapped,
        web_recon=web_recon,
        web_exploit=web_exploit,
        api_discovery=api_discovery,
        probe_routes=probe_routes,
        plan_web_order=plan_web_order,
        planned_redteam=planned_redteam,
        native_tools=native_tools,
        llm_summary=llm_summary,
    )

    if max_rps:
        config.max_rps = max_rps

    phases = [ScanPhase.RECON] if recon_only else None
    orchestrator = Orchestrator(config=config, phases=phases, dry_run=dry_run)

    console.print("[yellow]→[/yellow] Starting pipeline...")
    session = orchestrator.run(target, authorized_scope=list(scope))

    from cyberai.cli.replay import save_session

    saved = save_session(session, config.output_dir)
    # A checkmark over a failed run reads as "we looked and this is what is
    # there". The findings line is identical either way, so the mark is the
    # only thing telling the reader whether the pipeline actually ran.
    failed = [p.phase.value for p in session.phases if not p.success]
    # A phase that ran but could not look is not a failure -- the pipeline
    # deliberately carries on when nmap is missing or a host never answered --
    # yet it must not be reported as a completed scan either.
    degraded = sorted(
        {
            f"{p.phase.value}/{part}"
            for p in session.phases
            for part in ((p.data or {}).get("degraded") or [])
        }
    )
    if failed:
        console.print(
            f"\n[red]x[/red] Incomplete. Findings: {len(session.findings)} "
            f"(failed: {', '.join(failed)})"
        )
    elif degraded:
        console.print(
            f"\n[yellow]![/yellow] Partial. Findings: {len(session.findings)} "
            f"(could not check: {', '.join(degraded)})"
        )
    else:
        console.print(f"\n[green]✓[/green] Done. Findings: {len(session.findings)}")
    plan_line = _plan_summary(session.kb.get("plan"))
    if plan_line:
        console.print(f"[dim]{plan_line}[/dim]")
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


cli.add_command(bench)
cli.add_command(mcp_scan)
cli.add_command(web3)

if __name__ == "__main__":
    cli()
