"""`cyberai web3 audit` — audit a Solidity contract and emit findings.

Runs the Web3 agent against a local ``.sol`` file (or a verified on-chain
address when an explorer key is configured) and prints the findings. With
``--immunefi`` each finding is rendered as an Immunefi bug-bounty submission
(VSCS v2.3 severity, funds-at-risk, and — for a confirmed Foundry PoC — the
on-chain proof), ready to paste into the Immunefi dashboard.
"""

from __future__ import annotations

import click
from rich.console import Console

from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.immunefi_report import build_immunefi_submissions
from cyberai.core.config import CyberAIConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.logger import AuditLogger
from cyberai.core.scan_session import ScanSession

console = Console()


@click.group()
def web3() -> None:
    """Audit smart contracts for loss-of-funds vulnerabilities.

    \b
    Examples:
      cyberai web3 audit contracts/Vault.sol
      cyberai web3 audit contracts/Vault.sol --immunefi
    """


@web3.command("audit")
@click.argument("target")
@click.option(
    "--immunefi",
    "as_immunefi",
    is_flag=True,
    help="Emit each finding as an Immunefi submission (Markdown)",
)
def audit(target: str, as_immunefi: bool) -> None:
    """Audit TARGET (a .sol path or a verified contract address)."""
    config = CyberAIConfig.from_env()
    session = ScanSession(target=target)
    llm = LLMClient(config.llm)
    audit_log = AuditLogger(session.session_id, output_dir=config.output_dir)
    agent = SmartContractAgent(config, session, llm, audit_log)

    result = agent.run(target)

    if as_immunefi:
        submissions = build_immunefi_submissions(result)
        if not submissions:
            console.print("[yellow]No findings to report.[/yellow]")
            return
        click.echo(("\n\n---\n\n").join(submissions))
        return

    console.print(
        f"[bold]Web3 audit[/bold] {target} ({result['mode']}) — "
        f"highest severity: {result.get('highest_severity', 'Insight')}"
    )
    for finding in result.get("findings", []):
        sev = finding.get("immunefi_severity", "Insight")
        console.print(f"  [cyan]{finding.get('check')}[/cyan] — {sev}")
