"""`cyberai registry-targets` — choose auditable targets from a registry dump.

Reads a JSON Lines dump of the published MCP server registry and prints the
entries whose repository can be reached, so that the source behind them can be
audited statically. Nothing here connects to the servers themselves: auditing
published code is one act, and connecting to somebody's running instance is
another one that needs their authorization.

The dump is passed as a file rather than fetched, which keeps the selection
reproducible and keeps the cost of collecting a registry out of the cost of
choosing from it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from cyberai.agents.mcp_scan.registry import select_targets

console = Console()


def _rows(path: Path) -> list[dict[str, Any]]:
    """Parse a JSON Lines dump, refusing a line that is not an object."""
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            raise click.ClickException(f"{path}:{number} is not a JSON object")
        rows.append(parsed)
    return rows


@click.command("registry-targets")
@click.argument("dump", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--limit",
    type=click.IntRange(min=1),
    default=None,
    help="Stop after this many candidate entries",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the selection as JSON")
def registry_targets(dump: Path, limit: int | None, as_json: bool) -> None:
    """Select auditable targets from a registry DUMP, checking each repository."""
    selection = select_targets(_rows(dump), limit=limit)

    if as_json:
        console.print_json(
            json.dumps(
                {
                    "candidates": selection.candidates,
                    "distinct_urls": selection.distinct_urls,
                    "chosen": [{"name": c.name, "url": c.url} for c in selection.chosen],
                    "unreachable": [{"name": c.name, "url": c.url} for c in selection.unreachable],
                    "unknown": [{"name": c.name, "url": c.url} for c in selection.unknown],
                }
            )
        )
        return

    console.print(f"[bold]registry targets[/bold] {dump} — {selection.summary()}")
    for candidate in selection.chosen:
        console.print(f"  [green]{candidate.name}[/green] {candidate.url}", highlight=False)
    # An entry that cannot be reached is reported, not dropped in silence: the
    # gap between what a registry lists and what it can serve is the finding.
    for candidate in selection.unreachable:
        console.print(f"  [red]unreachable[/red] {candidate.name} {candidate.url}", highlight=False)
    # Unknown is not a milder kind of unreachable. The host declined to answer,
    # and asking harder is not a remedy this command offers.
    for candidate in selection.unknown:
        console.print(
            f"  [yellow]unknown[/yellow] {candidate.name} {candidate.url}", highlight=False
        )
