"""
/api/lab — read-only view over local practice-lab machines.

Machine folders live under config.lab_machines_dir (each subdirectory is one
machine). This router lists them and renders a Markdown writeup per machine by
reusing the offline lab tooling; it never runs a scan or touches the network.
A missing or unconfigured directory yields an empty list rather than an error.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request

from cyberai.lab.runner import run_machine
from cyberai.lab.writeup import generate_writeup

router = APIRouter()


def _machines_dir(request: Request) -> Path | None:
    raw = getattr(request.app.state.config, "lab_machines_dir", None)
    return Path(raw) if raw else None


def _flag_patterns(request: Request) -> list[str]:
    return list(getattr(request.app.state.config, "lab_flag_patterns", []) or [])


@router.get("/lab/machines")
def list_machines(request: Request) -> dict:
    """List practice-lab machines and whether each is solved, sorted by name."""
    root = _machines_dir(request)
    machines: list[dict] = []
    if root is not None and root.is_dir():
        patterns = _flag_patterns(request)
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            result = run_machine(entry, extra_flag_patterns=patterns)
            machines.append(
                {
                    "name": result.name,
                    "solved": result.solved,
                    "flags": len(result.flags),
                    "artifacts": len(result.artifacts),
                }
            )
    return {"machines": machines, "count": len(machines)}


@router.get("/lab/machines/{name}")
def get_machine_writeup(name: str, request: Request) -> dict:
    """Return the Markdown writeup for one machine, or a not-found error dict."""
    root = _machines_dir(request)
    if root is None:
        return {"error": "lab machines dir not configured", "name": name}
    safe = Path(name).name
    machine_dir = root / safe
    if not machine_dir.is_dir():
        return {"error": "machine not found", "name": name}
    result = run_machine(machine_dir, extra_flag_patterns=_flag_patterns(request))
    return {"name": result.name, "markdown": generate_writeup(result)}
