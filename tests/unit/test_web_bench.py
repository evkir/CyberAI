"""Tests for the /api/bench dashboard routes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from cyberai.core.config import CyberAIConfig
from cyberai.web.app import create_app


@pytest.fixture
def client(tmp_path):
    cfg = CyberAIConfig()
    cfg.output_dir = tmp_path
    return TestClient(create_app(cfg))


def test_list_scorecards_empty(client):
    r = client.get("/api/bench/scorecards")
    assert r.status_code == 200
    assert r.json() == {"suites": [], "count": 0}


def test_list_and_get_scorecard(client, tmp_path):
    (tmp_path / "scorecard_local.md").write_text("# Scorecard local\npass@1: 5/5")
    (tmp_path / "scorecard_evmbench.md").write_text("# evm")
    r = client.get("/api/bench/scorecards")
    body = r.json()
    assert body["count"] == 2
    assert body["suites"] == ["evmbench", "local"]  # sorted

    r2 = client.get("/api/bench/scorecards/local")
    assert r2.status_code == 200
    assert "pass@1" in r2.json()["markdown"]
    assert r2.json()["suite"] == "local"


def test_get_scorecard_missing(client):
    r = client.get("/api/bench/scorecards/ghost")
    assert r.json()["error"] == "scorecard not found"


def test_get_scorecard_path_traversal_blocked(client, tmp_path):
    # Encoded slashes never match the route (404), and a dotted basename that
    # does reach the handler is treated as a plain filename, not a path.
    r = client.get("/api/bench/scorecards/..%2f..%2fetc%2fpasswd")
    assert r.status_code == 404
    r2 = client.get("/api/bench/scorecards/..config")
    assert r2.json()["error"] == "scorecard not found"


def test_trigger_disabled_by_default(client):
    r = client.post("/api/bench/run/local")
    assert r.json()["error"] == "bench trigger disabled"


def test_trigger_enabled_launches_subprocess(tmp_path):
    cfg = CyberAIConfig()
    cfg.output_dir = tmp_path
    cfg.web_enable_bench_trigger = True
    client = TestClient(create_app(cfg))
    with patch("cyberai.web.routes.bench.subprocess.Popen") as popen:
        r = client.post("/api/bench/run/local")
    assert r.json()["started"] is True
    assert r.json()["suite"] == "local"
    popen.assert_called_once()
    # The launched argv targets the bench CLI with a scorecard output path.
    argv = popen.call_args[0][0]
    assert "bench" in argv and "run" in argv
    assert str(tmp_path) in argv[-1]


def test_trigger_sanitises_suite_name(tmp_path):
    cfg = CyberAIConfig()
    cfg.output_dir = tmp_path
    cfg.web_enable_bench_trigger = True
    client = TestClient(create_app(cfg))
    with patch("cyberai.web.routes.bench.subprocess.Popen") as popen:
        # A dotted name reaches the handler; Path().name keeps it a basename.
        r = client.post("/api/bench/run/..evil")
    assert r.json()["suite"] == "..evil"
    argv = popen.call_args[0][0]
    # The scorecard path stays inside output_dir — no escape.
    assert str(tmp_path) in argv[-1]


def test_scorecard_unreadable(client, tmp_path, monkeypatch):
    (tmp_path / "scorecard_local.md").write_text("x")

    def boom(self, *a, **k):
        raise OSError("nope")

    monkeypatch.setattr(Path, "read_text", boom)
    r = client.get("/api/bench/scorecards/local")
    assert r.json()["error"] == "scorecard unreadable"
