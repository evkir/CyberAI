"""
/api/sessions/{id}/report — serve a session's generated markdown report.

The report path is resolved from the session's knowledge base
(report.markdown_path), written by ReportAgent. Falls back to a 404-shaped
error dict when a session has no report (e.g. dry-run scans).
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

router = APIRouter()


def _sessions_dir(request: Request) -> Path:
    return Path(request.app.state.config.output_dir)


def _report_path_for(session: dict) -> str | None:
    kb = session.get("kb")
    if isinstance(kb, dict):
        val = kb.get("report.markdown_path")
        if isinstance(val, dict):  # kb entries may wrap value+meta
            val = val.get("value")
        if isinstance(val, str):
            return val
    return None


@router.get("/sessions/{session_id}/report", response_class=PlainTextResponse)
def get_report(session_id: str, request: Request):
    """Return the markdown report body for a session, or an error dict."""
    out = _sessions_dir(request)
    safe = Path(session_id).name
    spath = out / f"session_{safe}.json"
    if not spath.exists():
        return PlainTextResponse(
            json.dumps({"error": "session not found"}),
            status_code=404,
            media_type="application/json",
        )
    session = json.loads(spath.read_text())

    md = _report_path_for(session)
    # Guard traversal: report must live inside the sessions dir.
    if md:
        rp = Path(md)
        if rp.name == rp.as_posix().split("/")[-1] and rp.exists():
            try:
                rp.resolve().relative_to(out.resolve())
            except ValueError:
                md = None
            else:
                return PlainTextResponse(rp.read_text(), media_type="text/markdown")

    return PlainTextResponse(
        json.dumps({"error": "no report for session", "session_id": session_id}),
        status_code=404,
        media_type="application/json",
    )
