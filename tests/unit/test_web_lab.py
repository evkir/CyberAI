"""Tests for the /api/lab dashboard routes."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from cyberai.core.config import CyberAIConfig
from cyberai.web.app import create_app


def _machine(root: Path, name: str, *, flag: str | None = None) -> None:
    m = root / name
    (m / "nmap").mkdir(parents=True)
    (m / "nmap" / "scan.txt").write_text("22/tcp open")
    if flag is not None:
        (m / "loot").mkdir(parents=True)
        (m / "loot" / "proof.txt").write_text(flag)


def _client(machines_dir: Path | None, patterns=None, *, enabled: bool = True) -> TestClient:
    """A client for the lab routes, with the feature on unless asked otherwise.

    The tests below are about what the routes report once the operator has
    turned the feature on, so the flag defaults to on here and the two cases
    that assert the refusal pass enabled=False.
    """
    cfg = CyberAIConfig()
    cfg.use_lab_dogfood = enabled
    if machines_dir is not None:
        cfg.lab_machines_dir = str(machines_dir)
    if patterns is not None:
        cfg.lab_flag_patterns = patterns
    return TestClient(create_app(cfg))


def test_machines_refused_unless_enabled(tmp_path):
    """Disabled is not the same answer as unconfigured.

    Both used to produce an empty list, which is why the flag could gate
    nothing for as long as it did: a configured directory served machines
    whether or not the documented switch was on. The refusal names itself
    so the two are distinguishable from the outside.
    """
    _machine(tmp_path, "brainpan", flag="a" * 32)
    client = _client(tmp_path, enabled=False)
    body = client.get("/api/lab/machines").json()
    assert body["error"] == "lab dogfood disabled"
    assert body["count"] == 0


def test_writeup_refused_unless_enabled(tmp_path):
    _machine(tmp_path, "brainpan", flag="a" * 32)
    client = _client(tmp_path, enabled=False)
    body = client.get("/api/lab/machines/brainpan").json()
    assert body["error"] == "lab dogfood disabled"
    assert "markdown" not in body


def test_machines_unconfigured_is_empty():
    """Enabled but with no directory named: an empty list, not a refusal."""
    client = _client(None)
    r = client.get("/api/lab/machines")
    assert r.json() == {"machines": [], "count": 0}


def test_machines_missing_dir_is_empty(tmp_path):
    client = _client(tmp_path / "ghost")
    r = client.get("/api/lab/machines")
    assert r.json()["count"] == 0


def test_list_machines_solved_and_unsolved(tmp_path):
    _machine(tmp_path, "brainpan", flag="0123456789abcdef0123456789abcdef")
    _machine(tmp_path, "empty")
    client = _client(tmp_path)
    body = client.get("/api/lab/machines").json()
    assert body["count"] == 2
    by_name = {m["name"]: m for m in body["machines"]}
    assert by_name["brainpan"]["solved"] is True
    assert by_name["brainpan"]["flags"] >= 1
    assert by_name["empty"]["solved"] is False


def test_list_skips_non_directories(tmp_path):
    _machine(tmp_path, "box1", flag="a" * 32)
    (tmp_path / "loose_file.txt").write_text("not a machine")
    client = _client(tmp_path)
    body = client.get("/api/lab/machines").json()
    assert body["count"] == 1
    assert body["machines"][0]["name"] == "box1"


def test_machine_writeup(tmp_path):
    _machine(tmp_path, "brainpan", flag="f" * 32)
    client = _client(tmp_path)
    r = client.get("/api/lab/machines/brainpan")
    assert r.json()["name"] == "brainpan"
    assert "# Lab Writeup: brainpan" in r.json()["markdown"]
    assert "SOLVED" in r.json()["markdown"]


def test_machine_writeup_unconfigured(tmp_path):
    client = _client(None)
    r = client.get("/api/lab/machines/whatever")
    assert r.json()["error"] == "lab machines dir not configured"


def test_machine_writeup_missing(tmp_path):
    _machine(tmp_path, "box1", flag="a" * 32)
    client = _client(tmp_path)
    r = client.get("/api/lab/machines/ghost")
    assert r.json()["error"] == "machine not found"


def test_extra_flag_patterns_applied(tmp_path):
    m = tmp_path / "custom"
    (m / "loot").mkdir(parents=True)
    (m / "loot" / "notes.txt").write_text("KEY-2026-ABC")
    client = _client(tmp_path, patterns=[r"KEY-\d{4}-[A-Z]+"])
    body = client.get("/api/lab/machines").json()
    assert body["machines"][0]["solved"] is True
