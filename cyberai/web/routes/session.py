"""
/api/sessions — list and inspect scan sessions read from disk.

Sessions live as session_<id>.json in config.output_dir, written by the
CLI scan flow (cyberai.cli.replay.save_session). This router never mutates
them; it is a read-only window for the dashboard.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter()

_SESSION_GLOB = "session_*.json"


def _sessions_dir(request: Request) -> Path:
    return Path(request.app.state.config.output_dir)


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _summary(data: dict) -> dict:
    """Compact view for the list endpoint."""
    return {
        "session_id": data.get("session_id"),
        "target": data.get("target"),
        "state": data.get("state"),
        "created_at": data.get("created_at"),
        "ended_at": data.get("ended_at"),
        "findings": len(data.get("findings") or []),
    }


@router.get("/sessions")
def list_sessions(request: Request) -> dict:
    """List all sessions on disk, newest first."""
    out = _sessions_dir(request)
    items: list[dict] = []
    if out.exists():
        for path in out.glob(_SESSION_GLOB):
            data = _load(path)
            if data:
                items.append(_summary(data))
    items.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    return {"sessions": items, "count": len(items)}


@router.get("/sessions/{session_id}")
def get_session(session_id: str, request: Request) -> dict:
    """Full session JSON for one id, or a 404-shaped error dict."""
    safe = Path(session_id).name
    path = _sessions_dir(request) / f"session_{safe}.json"
    data = _load(path) if path.exists() else None
    if data is None:
        return {"error": "session not found", "session_id": session_id}
    return data


@router.get("/sessions/{session_id}/stream")
async def stream_session(session_id: str, request: Request) -> StreamingResponse:
    """
    SSE: poll the session file and emit phase deltas until terminal state.

    Emits `event: phase` for each newly-seen phase and `event: done` when
    the session reaches a terminal state or after a bounded number of polls.
    """
    safe = Path(session_id).name
    path = _sessions_dir(request) / f"session_{safe}.json"

    async def gen():
        seen: set[str] = set()
        terminal = {"completed", "failed", "error"}
        for _ in range(120):
            if await request.is_disconnected():
                return
            data = _load(path) if path.exists() else None
            if data:
                for ph in data.get("phases") or []:
                    name = ph.get("phase") or ph.get("name")
                    if name and name not in seen:
                        seen.add(name)
                        yield f"event: phase\ndata: {json.dumps(ph)}\n\n"
                state = data.get("state")
                if state and state.lower() in terminal:
                    yield f"event: done\ndata: {json.dumps({'state': state})}\n\n"
                    return
            await asyncio.sleep(0.5)
        yield 'event: done\ndata: {"state": "timeout"}\n\n'

    return StreamingResponse(gen(), media_type="text/event-stream")
