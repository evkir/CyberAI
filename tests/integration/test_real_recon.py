"""
Real-world e2e tests against scanme.nmap.org — the official nmap test target.

These tests perform live network calls and are marked @slow + @network so they
run only on the nightly CI workflow (and locally with `pytest -m slow`).
"""

import shutil

import pytest

from cyberai.agents.recon.nmap_tool import run_nmap

pytestmark = [pytest.mark.slow, pytest.mark.network]

SCANME_TARGET = "scanme.nmap.org"


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap binary not installed")
def test_real_nmap_finds_ssh_on_scanme():
    """
    scanme.nmap.org publicly advertises 22/tcp ssh as open.
    Light scan: top 100 ports, no version probes — minimal load on the target.
    """
    result = run_nmap(SCANME_TARGET, flags="-T4 --top-ports 100")

    assert "error" not in result, f"nmap failed: {result.get('error')}"
    assert result.get("returncode") == 0, f"nmap exit={result.get('returncode')}"

    ports = result.get("ports", [])
    assert len(ports) > 0, "no open ports parsed — output format may have changed"

    open_port_numbers = {p["port"] for p in ports if p.get("state") == "open"}
    assert 22 in open_port_numbers, (
        f"expected 22/tcp ssh on scanme.nmap.org, got {open_port_numbers}"
    )
