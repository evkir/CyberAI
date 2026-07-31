"""Tests for the optional MST (mas-sentry) MCP-fuzzing bridge."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from cyberai.agents.mcp_scan.mst_bridge import (
    MSTBridge,
    MSTFinding,
    build_target,
    find_mst,
    is_lab_target,
    map_severity,
)
from cyberai.core.scan_session import Severity


def test_find_mst_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "mas-sentry"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("MAS_SENTRY_PATH", str(fake))
    assert find_mst() == str(fake)


def test_find_mst_uses_path(monkeypatch):
    monkeypatch.delenv("MAS_SENTRY_PATH", raising=False)
    with patch(
        "cyberai.agents.mcp_scan.mst_bridge.shutil.which", return_value="/usr/bin/mas-sentry"
    ):
        assert find_mst() == "/usr/bin/mas-sentry"


def test_map_severity_known_and_fallback():
    assert map_severity("CRITICAL") is Severity.CRITICAL
    assert map_severity("high") is Severity.HIGH
    assert map_severity(" info ") is Severity.INFO
    assert map_severity("bogus") is Severity.INFO
    assert map_severity("") is Severity.INFO


def test_build_target_schemes():
    assert build_target("http://h:9090/mcp") == "http://h:9090/mcp"
    assert build_target("https://h/mcp") == "https://h/mcp"
    assert build_target("sse://h/mcp") == "https://h/mcp"
    assert build_target("stdio://python3 server.py") == "stdio://python3 server.py"
    assert build_target("python3 server.py") == "stdio://python3 server.py"


def test_is_lab_target():
    assert is_lab_target("stdio://python3 x.py") is True
    assert is_lab_target("http://localhost:9090/mcp") is True
    assert is_lab_target("http://127.0.0.1/mcp") is True
    assert is_lab_target("https://box.lab/mcp") is True
    assert is_lab_target("https://evil.example.com/mcp") is False


def test_available_false_without_path(monkeypatch):
    monkeypatch.delenv("MAS_SENTRY_PATH", raising=False)
    with patch("cyberai.agents.mcp_scan.mst_bridge.shutil.which", return_value=None):
        assert MSTBridge(mst_path=None).available is False


def test_fuzz_returns_empty_when_unavailable(monkeypatch):
    monkeypatch.delenv("MAS_SENTRY_PATH", raising=False)
    with patch("cyberai.agents.mcp_scan.mst_bridge.shutil.which", return_value=None):
        bridge = MSTBridge(mst_path=None)
    with patch("cyberai.agents.mcp_scan.mst_bridge.run_sealed") as run:
        assert bridge.fuzz("http://localhost/mcp") == []
        run.assert_not_called()


def test_fuzz_skips_nonlab_without_confirm(tmp_path):
    fake = tmp_path / "mas-sentry"
    fake.write_text("#!/bin/sh\n")
    bridge = MSTBridge(mst_path=str(fake))
    with patch("cyberai.agents.mcp_scan.mst_bridge.run_sealed") as run:
        assert bridge.fuzz("https://evil.example.com/mcp", confirm_scope=False) == []
        run.assert_not_called()


def test_fuzz_parses_report(tmp_path):
    fake = tmp_path / "mas-sentry"
    fake.write_text("#!/bin/sh\n")
    bridge = MSTBridge(mst_path=str(fake))

    payload = [
        {"check": "tool_poisoning", "severity": "HIGH", "detail": "hidden instruction"},
        {"check": "ssrf", "severity": "CRITICAL", "detail": "oob callback"},
        {"check": "weird", "severity": "banana", "detail": "unknown sev"},
    ]

    def _write_report(cmd, **kwargs):
        out = cmd[cmd.index("--out") + 1]
        Path(out).write_text(json.dumps(payload))

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()

    with patch("cyberai.agents.mcp_scan.mst_bridge.run_sealed", side_effect=_write_report) as run:
        findings = bridge.fuzz("stdio://python3 server.py")

    run.assert_called_once()
    cmd = run.call_args.args[0]
    assert cmd[:4] == [str(fake), "mcp", "scan", "--target"]
    assert "--confirm-scope" not in cmd  # stdio target is lab-safe
    assert [f.check for f in findings] == ["tool_poisoning", "ssrf", "weird"]
    assert findings[0].severity is Severity.HIGH
    assert findings[1].severity is Severity.CRITICAL
    assert findings[2].severity is Severity.INFO  # unknown -> INFO
    assert findings[0].to_dict() == {
        "check": "tool_poisoning",
        "severity": "HIGH",
        "detail": "hidden instruction",
    }


def test_fuzz_confirmed_nonlab_appends_flag(tmp_path):
    fake = tmp_path / "mas-sentry"
    fake.write_text("#!/bin/sh\n")
    bridge = MSTBridge(mst_path=str(fake))

    def _noop(cmd, **kwargs):
        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()

    with patch("cyberai.agents.mcp_scan.mst_bridge.run_sealed", side_effect=_noop) as run:
        bridge.fuzz("https://scope.example.com/mcp", confirm_scope=True)
    assert "--confirm-scope" in run.call_args.args[0]


def test_fuzz_uses_sealed_exec(tmp_path):
    """The MST child must not inherit the operator environment or HOME."""
    fake = tmp_path / "mas-sentry"
    fake.write_text("#!/bin/sh\n")
    bridge = MSTBridge(mst_path=str(fake))

    def _noop(cmd, **kwargs):
        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()

    with patch("cyberai.agents.mcp_scan.mst_bridge.run_sealed", side_effect=_noop) as run:
        bridge.fuzz("stdio://python3 server.py")
    kwargs = run.call_args.kwargs
    assert "home" not in kwargs  # synthetic home, not the operator's
    assert "capture_output" not in kwargs  # run_sealed applies it itself


def test_parse_report_missing_file():
    assert MSTBridge._parse_report("/no/such/file.json") == []


def test_parse_report_bad_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert MSTBridge._parse_report(str(bad)) == []


def test_msftinding_dataclass():
    f = MSTFinding(check="c", severity=Severity.LOW, detail="d")
    assert f.to_dict()["severity"] == "LOW"
