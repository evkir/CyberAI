"""
/api/lab — read-only view over local practice-lab machines.

Machine folders live under config.lab_machines_dir (each subdirectory is one
machine). This router lists them and renders a Markdown writeup per machine by
reusing the offline lab tooling; it never runs a scan or touches the network.
A missing or unconfigured directory yields an empty list rather than an error.

Off unless explicitly enabled via config.use_lab_dogfood, the same shape the
bench trigger uses. The field was documented as the gate for this feature
from the day it was added and gated nothing: both endpoints read
lab_machines_dir directly, so configuring a directory was the real switch
and the declared one moved nothing. A refusal is returned rather than the
route being left unmounted, because a 404 is indistinguishable from a typo
in the path.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request

from cyberai.lab.runner import run_machine
from cyberai.lab.writeup import generate_writeup

router = APIRouter()


def _enabled(request: Request) -> bool:
    """Whether the operator turned the lab feature on."""
    return bool(request.app.state.config.use_lab_dogfood)


def _machines_dir(request: Request) -> Path | None:
    raw = request.app.state.config.lab_machines_dir
    return Path(raw) if raw else None


def _flag_patterns(request: Request) -> list[str]:
    return list(request.app.state.config.lab_flag_patterns or [])


@router.get("/lab/machines")
def list_machines(request: Request) -> dict:
    """List practice-lab machines and whether each is solved, sorted by name."""
    if not _enabled(request):
        return {"error": "lab dogfood disabled", "machines": [], "count": 0}
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
    if not _enabled(request):
        return {"error": "lab dogfood disabled", "name": name}
    root = _machines_dir(request)
    if root is None:
        return {"error": "lab machines dir not configured", "name": name}
    safe = Path(name).name
    machine_dir = root / safe
    if not machine_dir.is_dir():
        return {"error": "machine not found", "name": name}
    result = run_machine(machine_dir, extra_flag_patterns=_flag_patterns(request))
    return {"name": result.name, "markdown": generate_writeup(result)}
