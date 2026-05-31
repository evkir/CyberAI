"""
/api/session — start scans, query session state.
"""

from flask import Blueprint, request, jsonify
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional
import uuid
import time
import threading

session_bp = Blueprint("session", __name__)

# In-memory session store (replaced by DB in production)
_sessions: Dict[str, dict] = {}
_lock = threading.Lock()


@dataclass
class SessionRecord:
    session_id: str
    target: str
    status: str = "pending"  # pending | running | done | error
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    result: dict = field(default_factory=dict)
    error: Optional[str] = None


@session_bp.post("/session")
def create_session():
    """
    POST /api/session
    Body: {"target": "10.10.10.1"}
    Returns: {"session_id": "...", "status": "pending"}
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    session_id = str(uuid.uuid4())
    record = SessionRecord(session_id=session_id, target=target)

    with _lock:
        _sessions[session_id] = asdict(record)

    # Fire pipeline in background thread
    thread = threading.Thread(
        target=_run_pipeline,
        args=(session_id, target),
        daemon=True,
    )
    thread.start()

    return jsonify(
        {
            "session_id": session_id,
            "target": target,
            "status": "pending",
        }
    ), 202


@session_bp.get("/session/<session_id>")
def get_session(session_id: str):
    """
    GET /api/session/<session_id>
    Returns session status and result when complete.
    """
    with _lock:
        record = _sessions.get(session_id)

    if not record:
        return jsonify({"error": "session not found"}), 404

    return jsonify(record)


@session_bp.get("/session")
def list_sessions():
    """GET /api/session — list all sessions"""
    with _lock:
        sessions = list(_sessions.values())
    return jsonify({"sessions": sessions, "count": len(sessions)})


def _run_pipeline(session_id: str, target: str):
    """Background worker: runs async pipeline, updates session record."""
    import asyncio
    from cyberai.core.pipeline import AsyncPipeline

    _update(session_id, status="running")
    try:
        pipeline = AsyncPipeline()
        result = asyncio.run(pipeline.run(target))
        _update(
            session_id,
            status="done" if result.success else "error",
            result=result.recon,
            completed_at=time.time(),
            error=result.error,
        )
    except Exception as e:
        _update(session_id, status="error", error=str(e), completed_at=time.time())


def _update(session_id: str, **kwargs):
    with _lock:
        if session_id in _sessions:
            _sessions[session_id].update(kwargs)
