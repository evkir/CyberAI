"""Tests for the behavioral probe adapter and its recon-agent wiring."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.agents.recon.behavioral_probe import (
    _MAX_BANNER_PROBES,
    _TOTAL_BUDGET,
    ProbeContext,
    _default_banner_grab,
    _default_http_get,
    _pick_http_port,
    _port_num,
    build_probe_context,
)
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession, Severity

# ── helpers: port parsing ─────────────────────────────────────────────


def test_port_num_variants():
    assert _port_num({"port": 22}) == 22
    assert _port_num({"portid": "80"}) == 80
    assert _port_num({}) is None
    assert _port_num({"port": "notint"}) is None


def test_pick_http_port_by_service_and_by_number():
    assert _pick_http_port([{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}]) == 80
    # Recognized by port number even when service label is blank.
    assert _pick_http_port([{"port": 8443, "service": ""}]) == 8443
    # Skips a malformed entry before finding the http port.
    assert _pick_http_port([{"port": None}, {"port": 443, "service": "https"}]) == 443
    assert _pick_http_port([{"port": 22, "service": "ssh"}]) is None


# ── build_probe_context ───────────────────────────────────────────────


def test_build_context_gathers_headers_banners_and_timing():
    ports = [{"port": 22, "service": "ssh"}, {"port": 443, "service": "https"}]
    http_get = MagicMock(return_value={"Server": "cloudflare"})
    banner_grab = MagicMock(side_effect=lambda h, p: f"banner-{p}")

    ctx = build_probe_context("t", ports, http_get=http_get, banner_grab=banner_grab)

    assert isinstance(ctx, ProbeContext)
    http_get.assert_called_once_with("https://t:443/")
    assert ctx.headers == {"Server": "cloudflare"}
    assert ctx.banners == ["banner-22", "banner-443"]
    # probe_fn times a banner grab on the first port and carries its output.
    res = ctx.probe_fn(0)
    assert res.banner == "banner-22"
    assert res.length == len("banner-22")
    assert res.latency >= 0.0


def test_build_context_http_url_scheme_and_empty_banner_skipped():
    ports = [{"port": 80, "service": "http"}]
    http_get = MagicMock(return_value={})
    banner_grab = MagicMock(return_value="")  # empty banner is not recorded

    ctx = build_probe_context("h", ports, http_get=http_get, banner_grab=banner_grab)

    http_get.assert_called_once_with("http://h:80/")
    assert ctx.banners == []


def test_build_context_no_http_port_skips_get_and_malformed_port():
    ports = [{"port": None}, {"port": 22, "service": "ssh"}]
    http_get = MagicMock()
    banner_grab = MagicMock(return_value="ssh-banner")

    ctx = build_probe_context("h", ports, http_get=http_get, banner_grab=banner_grab)

    http_get.assert_not_called()  # no HTTP(S) port present
    assert ctx.banners == ["ssh-banner"]  # malformed port skipped in the loop


def test_build_context_no_ports_probe_fn_is_neutral():
    ctx = build_probe_context("h", [], http_get=MagicMock(), banner_grab=MagicMock())
    res = ctx.probe_fn(0)
    assert res.latency == 0.0 and res.banner == ""


# ── default network primitives (failure paths, offline) ───────────────


def test_default_http_get_returns_headers_and_swallows_errors():
    client = MagicMock()
    client.__enter__.return_value.get.return_value = MagicMock(headers={"X": "1"})
    with patch("cyberai.agents.recon.behavioral_probe.httpx.Client", return_value=client):
        assert _default_http_get("http://x/") == {"X": "1"}

    with patch("cyberai.agents.recon.behavioral_probe.httpx.Client", side_effect=OSError("boom")):
        assert _default_http_get("http://x/") == {}


def test_default_banner_grab_reads_and_swallows_errors():
    conn = MagicMock()
    conn.__enter__.return_value.recv.return_value = b"SSH-2.0-x"
    with patch("cyberai.agents.recon.behavioral_probe.socket.create_connection", return_value=conn):
        assert _default_banner_grab("h", 22) == "SSH-2.0-x"

    with patch(
        "cyberai.agents.recon.behavioral_probe.socket.create_connection",
        side_effect=OSError("refused"),
    ):
        assert _default_banner_grab("h", 22) == ""


# ── recon-agent wiring (flag-gated) ───────────────────────────────────


def _run_recon(config):
    from cyberai.agents.recon.agent import ReconAgent

    session = ScanSession(target="t.local")
    agent = ReconAgent(config, session, MagicMock(), MagicMock())
    ok_nmap = {
        "target": "t.local",
        "ports": [{"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"}],
        "returncode": 0,
    }
    with (
        patch("cyberai.agents.recon.agent.run_nmap", return_value=ok_nmap),
        patch("cyberai.agents.recon.agent.run_whois", return_value={}),
        patch("cyberai.agents.recon.agent.run_dns", return_value={}),
        patch("cyberai.agents.recon.agent.detect_subdomains", return_value={}),
        patch("cyberai.agents.recon.agent.detect_llm_endpoints", return_value={}),
        patch(
            "cyberai.agents.recon.agent.build_probe_context",
            side_effect=lambda tgt, ports: _fake_ctx(),
        ) as mock_ctx,
    ):
        agent.run("t.local")
    return session, mock_ctx


def _fake_ctx():
    from cyberai.agents.recon.behavioral import ProbeResult
    from cyberai.agents.recon.behavioral_probe import ProbeContext

    return ProbeContext(
        probe_fn=lambda i: ProbeResult(latency=0.01),
        headers={"Server": "cloudflare", "CF-RAY": "x"},
        banners=["SSH-2.0-OpenSSH_9.6p1 Ubuntu"],
    )


def test_recon_runs_behavioral_when_flag_enabled():
    session, mock_ctx = _run_recon(CyberAIConfig(use_behavioral_fingerprint=True))
    mock_ctx.assert_called_once()
    trust = session.kb.get("recon.trust")
    assert trust is not None
    assert trust["signals"] == ["waf:cloudflare"]
    assert any(f.severity == Severity.INFO and "Behavioral" in f.title for f in session.findings)


def test_recon_skips_behavioral_when_flag_disabled():
    session, mock_ctx = _run_recon(CyberAIConfig())
    mock_ctx.assert_not_called()
    assert session.kb.get("recon.trust") is None


# -- probe bounds: cap + time budget --


def test_build_context_caps_banner_probes():
    """No more than max_probes banner grabs, even with many open ports."""
    ports = [{"port": 1000 + i, "service": "unknown"} for i in range(25)]
    banner_grab = MagicMock(return_value="b")
    build_probe_context(
        "h", ports, http_get=MagicMock(return_value={}), banner_grab=banner_grab, max_probes=3
    )
    assert banner_grab.call_count == 3


def test_build_context_stops_on_time_budget():
    """A clock that jumps past budget halts the banner loop early."""
    ports = [{"port": 1000 + i, "service": "unknown"} for i in range(25)]
    banner_grab = MagicMock(return_value="b")
    # now_fn: start=0, iter1=0, iter2=0, iter3=999 -> break after 2 grabs.
    clock = iter([0.0, 0.0, 0.0, 999.0])
    build_probe_context(
        "h",
        ports,
        http_get=MagicMock(return_value={}),
        banner_grab=banner_grab,
        max_probes=100,
        budget=10.0,
        now_fn=lambda: next(clock),
    )
    assert banner_grab.call_count == 2


def test_probe_bound_defaults_are_sane():
    assert _MAX_BANNER_PROBES > 0
    assert _TOTAL_BUDGET > 0


# -- mass-open guard: no probe spray on fake-ip targets --


def test_build_context_mass_open_skips_spray():
    """mass_open probes only the http port and the first port, plus a note."""
    ports = [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}]
    ports += [{"port": 1000 + i, "service": "unknown"} for i in range(300)]
    banner_grab = MagicMock(return_value="b")
    ctx = build_probe_context(
        "h", ports, http_get=MagicMock(return_value={}), banner_grab=banner_grab, mass_open=True
    )
    assert banner_grab.call_count == 2
    assert "mass-open" in ctx.note


def test_build_context_mass_open_no_http_port():
    """With no http port, mass_open probes only the first port."""
    ports = [{"port": 22, "service": "ssh"}] + [{"port": 1000 + i} for i in range(50)]
    banner_grab = MagicMock(return_value="b")
    ctx = build_probe_context(
        "h", ports, http_get=MagicMock(return_value={}), banner_grab=banner_grab, mass_open=True
    )
    assert banner_grab.call_count == 1
    assert ctx.note


def test_build_context_no_mass_open_has_empty_note():
    ports = [{"port": 80, "service": "http"}]
    ctx = build_probe_context(
        "h", ports, http_get=MagicMock(return_value={}), banner_grab=MagicMock(return_value="b")
    )
    assert ctx.note == ""
