"""Unit tests for nmap flag whitelist and result caching."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cyberai.agents.recon import nmap_tool
from cyberai.agents.recon.nmap_tool import run_nmap, validate_flags

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
    with patch.object(nmap_tool, "run_sealed", return_value=fake) as m:
        first = run_nmap("scanme.test", flags="-sV")
        second = run_nmap("scanme.test", flags="-sV")

    assert first["cached"] is False
    assert second["cached"] is True
    # subprocess.run called only once — second served from cache
    assert m.call_count == 1


def test_failed_scan_not_cached():
    """A non-zero return code must not be cached."""
    fake = _fake_proc(stdout="", rc=1)
    with patch.object(nmap_tool, "run_sealed", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
        run_nmap("scanme.test", flags="-sV")

    # both calls hit subprocess — nothing was cached
    assert m.call_count == 2


def test_different_flags_different_cache():
    """Different flags must not collide in the cache."""
    fake = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
        run_nmap("scanme.test", flags="-sV -Pn")

    # different flag strings -> two real scans
    assert m.call_count == 2


# ── timeout visibility & fast-retry resilience ────────────────────────

import subprocess  # noqa: E402

_XML_ONE_PORT = (
    '<port protocol="tcp" portid="80">'
    '<state state="open" reason="syn-ack"/>'
    '<service name="http"/>'
    "</port>"
)

_XML_ONE_PORT_SV = (
    '<port protocol="tcp" portid="80">'
    '<state state="open" reason="syn-ack"/>'
    '<service name="http" product="Apache httpd" version="2.4.52"/>'
    "</port>"
)


def test_timeout_returns_consistent_ports_shape():
    """A timeout must still yield a dict carrying an empty ports list so
    downstream consumers never hit a missing key."""
    with patch.object(
        nmap_tool,
        "run_sealed",
        side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=180),
    ) as m:
        res = run_nmap("scanme.test", flags="-T4")
    assert res["ports"] == []
    assert res.get("timed_out") is True
    assert "timeout" in res["error"]
    assert m.call_count == 1  # no -sV -> no fast retry


def test_sV_discovery_then_scoped_recovers_versions():
    """discovery-first: a fast version-less pass finds the open ports, then a
    scoped -sV re-probe recovers product/version. No degraded marker."""
    disco = _fake_proc(stdout=_XML_ONE_PORT, rc=0)  # port 80, no product
    targeted = _fake_proc(stdout=_XML_ONE_PORT_SV, rc=0)  # port 80 with product
    with patch.object(
        nmap_tool,
        "run_sealed",
        side_effect=[disco, targeted],
    ) as m:
        res = run_nmap("scanme.test", flags="-sV -T4 --top-ports 1000")
    assert m.call_count == 2  # discovery + scoped -sV
    assert "degraded" not in res  # versions recovered
    assert res["ports"][0]["product"] == "Apache httpd"
    # scoped -sV must target only the discovered port, not the full top-1000.
    scoped_argv = m.call_args_list[1][0][0]
    assert "-sV" in scoped_argv
    assert "-p" in scoped_argv
    assert "80" in scoped_argv
    assert "--top-ports" not in scoped_argv


def test_sV_scoped_reprobe_fails_marks_degraded():
    """If the scoped -sV re-probe fails (filtering net, no banners) the
    version-less discovery result is returned marked degraded — ports kept,
    versions not."""
    disco = _fake_proc(stdout=_XML_ONE_PORT, rc=0)  # port 80, no product
    scoped_timeout = subprocess.TimeoutExpired(cmd="nmap", timeout=90)
    with patch.object(
        nmap_tool,
        "run_sealed",
        side_effect=[disco, scoped_timeout],
    ) as m:
        res = run_nmap("scanme.test", flags="-sV -T4 --top-ports 1000")
    assert m.call_count == 2
    assert res["degraded"] == "sV_timeout_fast_retry"
    assert res["ports"][0]["port"] == 80  # open ports still recovered
    assert not res["ports"][0]["product"]  # but no version


def test_sV_no_open_ports_skips_scoped_scan():
    """When discovery finds no open ports, run_nmap does not attempt a scoped
    -sV and returns the version-less discovery result marked degraded."""
    empty = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)  # no open ports
    with patch.object(
        nmap_tool,
        "run_sealed",
        side_effect=[empty],
    ) as m:
        res = run_nmap("scanme.test", flags="-sV -T4 --top-ports 1000")
    assert m.call_count == 1  # discovery only, no scoped scan
    assert res["degraded"] == "sV_timeout_fast_retry"
    assert res["ports"] == []


def test_nmap_detaches_stdin_to_protect_terminal():
    """nmap must run with stdin detached so its runtime keypress interaction
    never leaves the analyst's terminal in no-echo/raw mode."""
    fake = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
    _, kwargs = m.call_args
    assert kwargs.get("stdin") == subprocess.DEVNULL


def test_nmap_uses_sealed_exec():
    """nmap talks to the scan target; the child must not inherit our env."""
    fake = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
    kwargs = m.call_args.kwargs
    assert "home" not in kwargs  # synthetic home, not the operator's
    assert "capture_output" not in kwargs  # run_sealed applies it itself


def test_nmap_runs_noninteractive():
    """nmap must be invoked with --noninteractive so its keypress reader never
    opens /dev/tty and corrupts the analyst's terminal echo."""
    fake = _fake_proc(stdout="<nmaprun></nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", return_value=fake) as m:
        run_nmap("scanme.test", flags="-sV")
    argv = m.call_args[0][0]
    assert "--noninteractive" in argv


# ── product/version capture (version-aware CVE matching foundation) ────

_XML_SV_PORT = (
    '<port protocol="tcp" portid="22">'
    '<state state="open" reason="syn-ack"/>'
    '<service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu" '
    'method="probed" conf="10">'
    "<cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe>"
    "</service>"
    "</port>"
)


def test_parse_ports_captures_product_and_version():
    ports = nmap_tool._parse_ports(_XML_SV_PORT)
    assert len(ports) == 1
    assert ports[0]["service"] == "ssh"
    assert ports[0]["product"] == "OpenSSH"
    assert ports[0]["version"] == "6.6.1p1 Ubuntu"


def test_parse_ports_missing_product_version_defaults_empty():
    """Self-closing <service name=.../> (no -sV data) yields empty strings,
    never missing keys, so downstream consumers stay total."""
    ports = nmap_tool._parse_ports(_XML_ONE_PORT)
    assert len(ports) == 1
    assert ports[0]["service"] == "http"
    assert ports[0]["product"] == ""
    assert ports[0]["version"] == ""


# ── mass-open (fake-ip proxy / tarpit) guard ──────────────────────────


def test_mass_open_flags_untrusted_scan():
    """A scan with implausibly many open ports (fake-ip proxy / tarpit) is
    flagged mass_open so intel can skip a meaningless CVE spray."""
    many = "".join(
        f'<port protocol="tcp" portid="{i}">'
        '<state state="open" reason="syn-ack"/>'
        f'<service name="svc{i}"/></port>'
        for i in range(1, 151)
    )
    fake = _fake_proc(stdout=f"<nmaprun>{many}</nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", return_value=fake):
        res = run_nmap("scanme.test", flags="-sV")
    assert res.get("mass_open") is True
    assert res["open_count"] == 150


def test_normal_scan_not_flagged_mass_open():
    fake = _fake_proc(stdout=f"<nmaprun>{_XML_ONE_PORT}</nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", return_value=fake):
        res = run_nmap("scanme.test", flags="-sV")
    assert res.get("mass_open") is None
    assert res["ports"] and res["ports"][0]["port"] == 80


# ── discovery / mass-open helpers ─────────────────────────────────────


def test_strip_sv_removes_only_sV():
    assert nmap_tool._strip_sv(["-sV", "-T4", "--top-ports", "1000"]) == [
        "-T4",
        "--top-ports",
        "1000",
    ]


def test_strip_sv_preserves_port_scope():
    assert nmap_tool._strip_sv(["-sV", "-p", "80,443", "-Pn"]) == [
        "-p",
        "80,443",
        "-Pn",
    ]


def test_strip_sv_noop_without_sV():
    assert nmap_tool._strip_sv(["-T4", "--top-ports", "100"]) == [
        "-T4",
        "--top-ports",
        "100",
    ]


def test_mark_mass_open_flags_and_returns_true():
    parsed = {"ports": [{"port": i, "state": "open"} for i in range(1, 151)]}
    assert nmap_tool._mark_mass_open(parsed) is True
    assert parsed["mass_open"] is True
    assert parsed["open_count"] == 150


def test_mark_mass_open_below_threshold_returns_false():
    parsed = {"ports": [{"port": 80, "state": "open"}]}
    assert nmap_tool._mark_mass_open(parsed) is False
    assert "mass_open" not in parsed
    assert "open_count" not in parsed


# ── discovery-first guarantees ────────────────────────────────────────


def test_mass_open_skips_sV_entirely():
    """On a mass-open discovery result (fake-ip / tunnel / tarpit) run_nmap must
    NOT run -sV at all: exactly one version-less scan, no version spray. A
    single-element side_effect makes any second nmap call raise loudly."""
    many = "".join(
        f'<port protocol="tcp" portid="{i}">'
        '<state state="open" reason="syn-ack"/>'
        f'<service name="svc{i}"/></port>'
        for i in range(1, 151)
    )
    disco = _fake_proc(stdout=f"<nmaprun>{many}</nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", side_effect=[disco]) as m:
        res = run_nmap("scanme.test", flags="-sV -T4 --top-ports 1000")
    assert res["mass_open"] is True
    assert res["open_count"] == 150
    assert m.call_count == 1  # discovery only — no scoped -sV
    assert "-sV" not in m.call_args_list[0][0][0]  # discovery carries no -sV


def test_discovery_pass_is_version_less_and_keeps_scope():
    """The discovery pass strips -sV but preserves the requested port scope."""
    disco = _fake_proc(stdout=_XML_ONE_PORT, rc=0)
    targeted = _fake_proc(stdout=_XML_ONE_PORT_SV, rc=0)
    with patch.object(nmap_tool, "run_sealed", side_effect=[disco, targeted]) as m:
        run_nmap("scanme.test", flags="-sV -T4 --top-ports 1000")
    disco_argv = m.call_args_list[0][0][0]
    assert "-sV" not in disco_argv
    assert "--top-ports" in disco_argv  # scope preserved


def test_non_sV_scan_single_pass_no_discovery():
    """A caller passing explicit non-sV flags gets one scan, no discovery-first."""
    fake = _fake_proc(stdout=f"<nmaprun>{_XML_ONE_PORT}</nmaprun>", rc=0)
    with patch.object(nmap_tool, "run_sealed", side_effect=[fake]) as m:
        res = run_nmap("scanme.test", flags="-T4 --top-ports 100")
    assert m.call_count == 1
    assert res["ports"][0]["port"] == 80
