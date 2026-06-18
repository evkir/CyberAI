"""Unit tests for the FastAPI dashboard backend (day 28)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyberai.core.config import CyberAIConfig
from cyberai.web.app import create_app


def _write_session(out: Path, sid: str, *, state: str = "completed", md: str | None = None) -> None:
    data = {
        "session_id": sid,
        "target": "example.com",
        "state": state,
        "created_at": "2026-06-18T10:00:00+00:00",
        "ended_at": "2026-06-18T10:00:05+00:00",
        "findings": [{"id": "F1"}],
        "phases": [
            {"phase": "recon", "success": True, "data": {}},
            {"phase": "report", "success": True, "data": {}},
        ],
        "kb": {"report.markdown_path": str(out / f"report_{sid}.md")} if md else {},
    }
    (out / f"session_{sid}.json").write_text(json.dumps(data))
    if md:
        (out / f"report_{sid}.md").write_text(md)


@pytest.fixture
def client(tmp_path):
    cfg = CyberAIConfig()
    cfg.output_dir = tmp_path
    return TestClient(create_app(cfg))


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_list_sessions_empty(client):
    r = client.get("/api/sessions")
    assert r.status_code == 200
    assert r.json() == {"sessions": [], "count": 0}


def test_list_and_get_session(client, tmp_path):
    _write_session(tmp_path, "aaaa1111")
    r = client.get("/api/sessions")
    body = r.json()
    assert body["count"] == 1
    assert body["sessions"][0]["session_id"] == "aaaa1111"
    assert body["sessions"][0]["findings"] == 1

    r2 = client.get("/api/sessions/aaaa1111")
    assert r2.json()["target"] == "example.com"


def test_get_session_missing(client):
    r = client.get("/api/sessions/nope")
    assert "error" in r.json()


def test_report_present(client, tmp_path):
    _write_session(tmp_path, "bbbb2222", md="# Report\nfindings here")
    r = client.get("/api/sessions/bbbb2222/report")
    assert r.status_code == 200
    assert "# Report" in r.text


def test_report_absent_for_dryrun(client, tmp_path):
    _write_session(tmp_path, "cccc3333")  # no md
    r = client.get("/api/sessions/cccc3333/report")
    assert r.status_code == 404


def test_sse_stream_terminal(client, tmp_path):
    _write_session(tmp_path, "dddd4444", state="completed")
    with client.stream("GET", "/api/sessions/dddd4444/stream") as r:
        assert r.status_code == 200
        chunks = "".join(r.iter_text())
    assert "event: phase" in chunks
    assert "event: done" in chunks
