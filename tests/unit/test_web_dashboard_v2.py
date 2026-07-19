"""Tests for the v2 tabbed dashboard template."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cyberai.core.config import CyberAIConfig
from cyberai.web.app import create_app


@pytest.fixture
def client(tmp_path):
    cfg = CyberAIConfig()
    cfg.output_dir = tmp_path
    return TestClient(create_app(cfg))


def test_dashboard_has_three_tabs(client):
    html = client.get("/").text
    assert "tab==='sessions'" in html
    assert "tab==='benchmarks'" in html
    assert "tab==='lab'" in html


def test_dashboard_wires_new_endpoints(client):
    html = client.get("/").text
    assert "/api/bench/scorecards" in html
    assert "/api/bench/regression/" in html
    assert "/api/lab/machines" in html


def test_dashboard_keeps_sessions_view(client):
    # The original sessions functionality must remain intact.
    html = client.get("/").text
    assert "/api/sessions" in html
    assert "EventSource" in html
