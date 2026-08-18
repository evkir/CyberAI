"""
/api/bench — read saved benchmark scorecards and optionally trigger a run.

Scorecards are Markdown files written to config.output_dir by the bench CLI
(`cyberai bench run --scorecard <path>`); this router only reads them. A run
can also be triggered from the dashboard, but only when explicitly enabled via
config.web_enable_bench_trigger — otherwise the endpoint refuses. Triggering
launches the bench CLI as a detached subprocess and never blocks the request.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, Request

router = APIRouter()

_SCORECARD_GLOB = "scorecard_*.md"


def _out_dir(request: Request) -> Path:
    return Path(request.app.state.config.output_dir)


def _suite_of(path: Path) -> str:
    """scorecard_<suite>.md -> <suite>."""
    return path.stem[len("scorecard_") :]


@router.get("/bench/scorecards")
def list_scorecards(request: Request) -> dict:
    """List saved scorecards by suite name, sorted."""
    out = _out_dir(request)
    suites: list[str] = []
    if out.exists():
        suites = sorted(_suite_of(p) for p in out.glob(_SCORECARD_GLOB))
    return {"suites": suites, "count": len(suites)}


@router.get("/bench/scorecards/{suite}")
def get_scorecard(suite: str, request: Request) -> dict:
    """Return one suite's scorecard Markdown, or a not-found error dict."""
    safe = Path(suite).name
    path = _out_dir(request) / f"scorecard_{safe}.md"
    if not path.is_file():
        return {"error": "scorecard not found", "suite": suite}
    try:
        body = path.read_text()
    except OSError:
        return {"error": "scorecard unreadable", "suite": suite}
    return {"suite": safe, "markdown": body}


@router.post("/bench/run/{suite}")
def trigger_run(suite: str, request: Request) -> dict:
    """Launch a bench run as a detached subprocess, if enabled in config.

    Disabled by default: returns a refusal dict unless
    config.web_enable_bench_trigger is True. The scorecard is written to
    config.output_dir/scorecard_<suite>.md for a later read.
    """
    config = request.app.state.config
    if not config.web_enable_bench_trigger:
        return {"error": "bench trigger disabled", "suite": suite}
    safe = Path(suite).name
    out = _out_dir(request)
    out.mkdir(parents=True, exist_ok=True)
    scorecard = out / f"scorecard_{safe}.md"
    cmd = [
        sys.executable,
        "-m",
        "cyberai",
        "bench",
        "run",
        "--suite",
        safe,
        "--scorecard",
        str(scorecard),
    ]
    # Fixed argv; suite name is sanitised to a basename above.
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return {"started": True, "suite": safe, "scorecard": str(scorecard)}
