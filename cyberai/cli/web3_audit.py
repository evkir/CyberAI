"""`cyberai web3 audit` — audit a Solidity contract and emit findings.

Runs the Web3 agent against a local ``.sol`` file (or a verified on-chain
address when an explorer key is configured) and prints the findings. With
``--immunefi`` each finding is rendered as an Immunefi bug-bounty submission
(VSCS v2.3 severity, funds-at-risk, and — for a confirmed Foundry PoC — the
on-chain proof), ready to paste into the Immunefi dashboard.
"""

from __future__ import annotations

from typing import Any

import click
from rich.console import Console

from cyberai.agents.web3.agent import SmartContractAgent
from cyberai.agents.web3.immunefi_report import build_immunefi_submissions, immunefi_tier
from cyberai.core.config import CyberAIConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.logger import AuditLogger
from cyberai.core.scan_session import ScanSession

# highlight=False: rich would otherwise colour numbers inside these lines
# and split short tokens with escape sequences (rule 103).
console = Console(highlight=False)


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
@click.option(
    "--foundry-project",
    type=click.Path(exists=True, file_okay=False),
    help="Foundry project root with an exploit test; enables on-chain PoC replay",
)
@click.option("--fork-rpc", help="Fork RPC url for the PoC replay (forge --fork-url)")
@click.option(
    "--poc-match", default="testExploit", show_default=True, help="Exploit test name to run"
)
@click.option(
    "--halmos-project",
    type=click.Path(exists=True, file_okay=False),
    help="Project root for symbolic testing with halmos",
)
@click.option("--halmos-contract", help="Symbolic test contract for halmos")
@click.option("--halmos-loop", type=int, default=2, show_default=True, help="halmos loop bound")
def audit(
    target: str,
    as_immunefi: bool,
    foundry_project: str | None,
    fork_rpc: str | None,
    poc_match: str,
    halmos_project: str | None,
    halmos_contract: str | None,
    halmos_loop: int,
) -> None:
    """Audit TARGET (a .sol path or a verified contract address).

    Symbolic testing and on-chain PoC replay need a prepared project root, so
    they run only when one is given. Immunefi requires a PoC at every severity
    level: without --foundry-project the audit cannot produce one.
    """
    config = CyberAIConfig.from_env()
    session = ScanSession(target=target)
    llm = LLMClient(config.llm)
    audit_log = AuditLogger(session.session_id, output_dir=config.output_dir)
    agent = SmartContractAgent(config, session, llm, audit_log)

    context = _build_context(
        foundry_project=foundry_project,
        fork_rpc=fork_rpc,
        poc_match=poc_match,
        halmos_project=halmos_project,
        halmos_contract=halmos_contract,
        halmos_loop=halmos_loop,
    )
    result = agent.run(target, context=context)

    if as_immunefi:
        submissions = build_immunefi_submissions(result)
        if not submissions:
            console.print("[yellow]No findings to report.[/yellow]")
            return
        click.echo(("\n\n---\n\n").join(submissions))
        return

    _print_audit(target, result)


def _build_context(**options: Any) -> dict[str, Any]:
    """Collect the tool options the agent reads out of `context`.

    The agent has taken a context since the halmos and foundry runners landed,
    but the CLI called run() with the target alone, so poc_findings and
    halmos_findings were structurally zero on every live audit — an unreachable
    code path, not a quiet result.
    """
    context = {k: v for k, v in options.items() if v is not None}
    if not context.get("foundry_project"):
        context.pop("poc_match", None)
        context.pop("fork_rpc", None)
    if not context.get("halmos_project"):
        context.pop("halmos_contract", None)
        context.pop("halmos_loop", None)
    return context


def _print_audit(target: str, result: dict[str, Any]) -> None:
    """Print every bucket the agent produced, not just the slither one.

    `findings` holds slither output alone. Printing it and nothing else meant
    aderyn detections, the SWC merge that cross-validates them, and the
    access-control analysis were computed on every run and thrown away — the
    parts that make this more than a slither wrapper were the invisible ones.
    """
    console.print(
        f"[bold]Web3 audit[/bold] {target} ({result['mode']}) — "
        f"highest severity: {result.get('highest_severity', 'Insight')}"
    )

    slither = result.get("findings") or []
    aderyn = result.get("aderyn_findings") or []
    merged = result.get("merged_findings") or []
    access = result.get("access_findings") or []
    paths = result.get("escalation_paths") or []
    poc = result.get("poc_findings") or []
    halmos = result.get("halmos_findings") or []
    crossed = sum(1 for m in merged if m.get("confidence") == "cross-validated")

    # Two counts of one audit: per-tool detections, and the SWC groups they fall
    # into. They differ because a weakness both tools found is a single group,
    # so neither number is wrong and neither replaces the other.
    console.print(
        f"  detections: slither {len(slither)}, aderyn {len(aderyn)}, "
        f"halmos {len(halmos)}, poc {len(poc)} | "
        f"swc groups: {len(merged)}, cross-validated: {crossed}"
    )

    # A result with no merge (an address-mode run, or a caller that only filled
    # the slither bucket) still has findings worth printing.
    for f in slither if not merged else ():
        console.print(f"  [cyan]{f.get('check')}[/cyan] — {f.get('immunefi_severity', 'Insight')}")

    for m in merged:
        sev = m.get("immunefi_severity", "Insight")
        swc = m.get("swc") or "no SWC"
        src = "+".join(m.get("sources") or [])
        mark = " [green]cross-validated[/green]" if m.get("confidence") == "cross-validated" else ""
        console.print(f"  [cyan]{m.get('check')}[/cyan] — {sev} — {swc} — {src}{mark}")

    # access findings carry impact/confidence and never a serialized tier: the
    # producer leaves classification to the consumer, so ask the same function
    # the Immunefi exporter asks instead of reading a key that is not there.
    for f in poc:
        profit = f.get("profit_wei")
        eth = f" — profit {int(profit) / 10**18:.6f} ETH" if profit else ""
        state = "confirmed" if f.get("confirmed") else "unconfirmed"
        console.print(f"  [red]poc[/red] {f.get('test', '?')} — {state}{eth}")

    for f in halmos:
        console.print(f"  [blue]halmos[/blue] {f.get('check', '?')} — {f.get('test', '?')}")

    for a in access:
        where = a.get("function") or a.get("contract") or "?"
        console.print(
            f"  [magenta]access[/magenta] {a.get('check')} — {immunefi_tier(a)} — {where}"
        )

    for esc in paths:
        unlocks = ", ".join(esc.get("unlocks") or []) or "nothing further"
        console.print(
            f"  [yellow]escalation[/yellow] {esc.get('entry', '?')} grants "
            f"{esc.get('grants', '?')} -> unlocks {unlocks}"
        )

    if not merged and not access and not slither and not poc:
        console.print("  no findings")
