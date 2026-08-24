"""Wiring tests for the flag-gated port fingerprint inside ReconAgent.

The module's own behaviour is covered against a real socket in
tests/unit/test_fingerprinter.py. What is untested there is the seam: whether
the agent calls it at all, whether the enriched list is the one that reaches
the knowledge base, and whether the two conditions that must suppress it --
the flag being off and nmap reporting a mass-open scan -- actually suppress
the connections rather than merely discarding their result.

Every suppression assertion is made on the call, not on the stored data. A
port list that comes back unchanged proves nothing about the network: the
probe may have run and its output been dropped, and the whole reason this
path is flag-gated is the traffic it generates.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cyberai.agents.recon.agent import ReconAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession

_RAW_PORTS = [
    {"port": 22, "protocol": "tcp", "service": "ssh", "product": "", "version": ""},
]
_ENRICHED_PORTS = [
    {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": "",
        "version": "",
        "banner": "[UNTRUSTED INPUT] SSH-2.0-OpenSSH_9.6 [/UNTRUSTED INPUT]",
    },
]


def _agent(**flags):
    session = ScanSession(target="t.local")
    agent = ReconAgent(CyberAIConfig(**flags), session, MagicMock(), MagicMock())
    return agent, session


@pytest.fixture
def recon_patches():
    """Patch every recon tool so only the fingerprint branch does work."""
    with (
        patch("cyberai.agents.recon.agent.run_whois", return_value={}),
        patch("cyberai.agents.recon.agent.run_dns", return_value={}),
        patch("cyberai.agents.recon.agent.enumerate_subdomains", return_value={}),
        patch("cyberai.agents.recon.agent.detect_llm_endpoints", return_value={}),
    ):
        yield


def _nmap(**extra):
    scan = {"target": "t.local", "ports": [dict(p) for p in _RAW_PORTS]}
    scan.update(extra)
    return scan


@pytest.mark.unit
def test_the_probe_does_not_run_when_the_flag_is_off(recon_patches):
    agent, session = _agent()
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=_nmap()),
        patch("cyberai.agents.recon.agent.fingerprint_ports") as spy,
    ):
        agent.run("t.local")

    spy.assert_not_called()
    assert session.kb.get("recon.nmap")["ports"] == _RAW_PORTS


@pytest.mark.unit
def test_the_enriched_list_is_the_one_stored_in_the_knowledge_base(recon_patches):
    """intel reads recon.nmap, so enrichment after the write would be invisible."""
    agent, session = _agent(use_port_fingerprint=True)
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=_nmap()),
        patch("cyberai.agents.recon.agent.fingerprint_ports", return_value=_ENRICHED_PORTS) as spy,
    ):
        agent.run("t.local")

    spy.assert_called_once_with("t.local", _RAW_PORTS)
    assert session.kb.get("recon.nmap")["ports"] == _ENRICHED_PORTS


@pytest.mark.unit
def test_a_mass_open_scan_is_not_probed(recon_patches):
    """The port list of a tunnelled scan describes the tunnel, not the host.

    Probing it would open a connection per phantom port, each paying the full
    connect timeout, which is the failure the mass_open flag exists to name.
    """
    agent, session = _agent(use_port_fingerprint=True)
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=_nmap(mass_open=True)),
        patch("cyberai.agents.recon.agent.fingerprint_ports") as spy,
    ):
        agent.run("t.local")

    spy.assert_not_called()
    assert session.kb.get("recon.nmap")["ports"] == _RAW_PORTS


@pytest.mark.unit
def test_a_failed_scan_is_not_probed(recon_patches):
    """A scan that errored has no measured port list to enrich."""
    agent, _ = _agent(use_port_fingerprint=True)
    failed = {"target": "t.local", "error": "nmap not found", "ports": _RAW_PORTS}
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=failed),
        patch("cyberai.agents.recon.agent.fingerprint_ports") as spy,
    ):
        agent.run("t.local")

    spy.assert_not_called()


@pytest.mark.unit
def test_a_scan_with_no_open_ports_is_not_probed(recon_patches):
    agent, _ = _agent(use_port_fingerprint=True)
    with (
        patch(
            "cyberai.agents.recon.agent.run_nmap", return_value={"target": "t.local", "ports": []}
        ),
        patch("cyberai.agents.recon.agent.fingerprint_ports") as spy,
    ):
        agent.run("t.local")

    spy.assert_not_called()


@pytest.mark.unit
def test_the_flag_is_read_from_the_environment(monkeypatch):
    """A field nothing maps to an env var is a flag only tests can set."""
    monkeypatch.setenv("CYBERAI_USE_PORT_FINGERPRINT", "1")
    assert CyberAIConfig.from_env().use_port_fingerprint is True


@pytest.mark.unit
def test_the_environment_flag_defaults_to_off(monkeypatch):
    """Control: without this the assertion above passes on a hardcoded True."""
    monkeypatch.delenv("CYBERAI_USE_PORT_FINGERPRINT", raising=False)
    assert CyberAIConfig.from_env().use_port_fingerprint is False
