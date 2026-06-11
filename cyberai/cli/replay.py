"""Session replay (day 21): reload a saved ScanSession and re-run it.

The saved session JSON (written by `cyberai scan`) is reloaded, the pipeline
is re-run in dry-run mode against the same target, and the replayed phases
are diffed against the originals. Replay is observability: same input ->
same deterministic pipeline shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanSession

console = Console()


def _session_path(output_dir: Path, session_id: str) -> Path:
    return output_dir / f"session_{session_id}.json"


def load_session(output_dir: Path, session_id: str) -> Optional[ScanSession]:
    """Load a saved session by id; None if the file is missing."""
    path = _session_path(output_dir, session_id)
    if not path.exists():
        return None
    return ScanSession.from_json(path.read_text())


def diff_phases(original: ScanSession, replayed: ScanSession) -> List[Dict[str, Any]]:
    """Compare phase success between the original and replayed sessions."""
    orig = {p.phase.value: p.success for p in original.phases}
    new = {p.phase.value: p.success for p in replayed.phases}
    rows: List[Dict[str, Any]] = []
    for phase in sorted(set(orig) | set(new)):
        o = orig.get(phase)
        n = new.get(phase)
        rows.append(
            {
                "phase": phase,
                "original": o,
                "replayed": n,
                "match": o == n,
            }
        )
    return rows


def run_replay(session_id: str, config: Optional[CyberAIConfig] = None) -> int:
    """Reload, re-run (dry-run) and diff a session. Returns process exit code."""
    config = config or CyberAIConfig.from_env()
    original = load_session(config.output_dir, session_id)
    if original is None:
        console.print(
            f"[red]✗[/red] No saved session [bold]{session_id}[/bold] in {config.output_dir}"
        )
        return 1

    console.print(
        f"[yellow]→[/yellow] Replaying session [bold]{session_id}[/bold] "
        f"(target: {original.target})"
    )
    orchestrator = Orchestrator(config=config, dry_run=True)
    replayed = orchestrator.run(original.target, authorized_scope=list(original.authorized_scope))

    rows = diff_phases(original, replayed)
    table = Table(title=f"Replay diff — {session_id}", style="cyan")
    table.add_column("Phase", style="bold")
    table.add_column("Original", justify="center")
    table.add_column("Replayed", justify="center")
    table.add_column("Match", justify="center")
    for r in rows:
        mark = "[green]✓[/green]" if r["match"] else "[red]✗[/red]"
        table.add_row(r["phase"], str(r["original"]), str(r["replayed"]), mark)
    console.print(table)

    all_match = all(r["match"] for r in rows)
    if all_match:
        console.print("[green]✓[/green] Replay deterministic — phases match.")
        return 0
    console.print("[red]✗[/red] Replay mismatch — pipeline not deterministic.")
    return 2


def save_session(session: ScanSession, output_dir: Path) -> Path:
    """Persist a session as session_<id>.json for later replay."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _session_path(output_dir, session.session_id)
    path.write_text(session.to_json())
    return path
