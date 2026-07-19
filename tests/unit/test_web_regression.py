"""Tests for the /api/bench/regression dashboard route."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyberai.core.config import CyberAIConfig
from cyberai.web.app import create_app


def _manifest(
    out: Path, kind: str, suite: str, *, solved: int, total: int, suite_hash: str = "h1"
) -> None:
    # kind is "manifest" (current) or "baseline".
    data = {
        "suite": suite,
        "engine_version": "1.3.0",
        "suite_hash": suite_hash,
        "solved": solved,
        "total": total,
        "timestamp": "2026-07-19T00:00:00Z",
    }
    (out / f"{kind}_{suite}.json").write_text(json.dumps(data))


@pytest.fixture
def client(tmp_path):
    cfg = CyberAIConfig()
    cfg.output_dir = tmp_path
    return TestClient(create_app(cfg))


def test_current_manifest_missing(client):
    r = client.get("/api/bench/regression/local")
    assert r.json()["error"] == "current manifest not found"


def test_no_baseline_passes(client, tmp_path):
    _manifest(tmp_path, "manifest", "local", solved=5, total=5)
    body = client.get("/api/bench/regression/local").json()
    assert body["passed"] is True
    assert body["has_baseline"] is False
    assert body["suite"] == "local"
    assert body["current_rate"] == 1.0


def test_held_or_improved_passes(client, tmp_path):
    _manifest(tmp_path, "baseline", "local", solved=4, total=5)
    _manifest(tmp_path, "manifest", "local", solved=5, total=5)
    body = client.get("/api/bench/regression/local").json()
    assert body["passed"] is True
    assert body["has_baseline"] is True
    assert body["baseline_rate"] == pytest.approx(0.8)
    assert body["current_rate"] == 1.0


def test_regression_fails(client, tmp_path):
    _manifest(tmp_path, "baseline", "local", solved=5, total=5)
    _manifest(tmp_path, "manifest", "local", solved=3, total=5)
    body = client.get("/api/bench/regression/local").json()
    assert body["passed"] is False
    assert "regressed" in body["reason"]


def test_suite_change_fails(client, tmp_path):
    _manifest(tmp_path, "baseline", "local", solved=5, total=5, suite_hash="old")
    _manifest(tmp_path, "manifest", "local", solved=5, total=5, suite_hash="new")
    body = client.get("/api/bench/regression/local").json()
    assert body["passed"] is False
    assert body["suite_changed"] is True


def test_path_traversal_reduced_to_basename(client, tmp_path):
    # An encoded-slash suite never matches the route.
    r = client.get("/api/bench/regression/..%2f..%2fetc")
    assert r.status_code == 404
