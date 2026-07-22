"""Live network adapter feeding BehavioralFingerprint from recon data.

Turns nmap open-port data into the ``probe_fn`` / ``headers`` / ``banners``
that :meth:`BehavioralFingerprint.run` consumes. The two network primitives
(an HTTP GET for WAF headers, a socket banner grab for honeypot/tarpit tells)
are injected as callables so the adapter is fully testable offline; each one
degrades to an empty result on any error. No new dependencies are introduced
(httpx already backs the recon package), preserving the air-gapped invariant.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

from .behavioral import ProbeResult

# Services / ports treated as HTTP(S) for the WAF header probe.
_HTTP_SERVICES = frozenset({"http", "https", "http-alt", "https-alt", "http-proxy"})
_HTTP_PORTS = frozenset({80, 443, 8080, 8443})
_TLS_PORTS = frozenset({443, 8443})

_CONNECT_TIMEOUT = 3.0
_HTTP_TIMEOUT = 5.0
_BANNER_BYTES = 256

# Bounds so a mass-open or slow-dripping (tarpit/honeypot) target cannot
# stall recon: cap the number of banner grabs and the total wall-clock time.
_MAX_BANNER_PROBES = 10
_TOTAL_BUDGET = 20.0

# url -> response headers; (host, port) -> banner text.
HttpGet = Callable[[str], Dict[str, str]]
BannerGrab = Callable[[str, int], str]


def _default_http_get(url: str) -> Dict[str, str]:
    """Fetch response headers via httpx; ``{}`` on any failure."""
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
        return dict(resp.headers)
    except Exception:
        return {}


def _default_banner_grab(host: str, port: int) -> str:
    """Grab a service banner via a short socket read; ``''`` on any failure."""
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            data = sock.recv(_BANNER_BYTES)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _port_num(port: Dict[str, Any]) -> Optional[int]:
    """Extract an int port number from an nmap port dict, or None."""
    raw = port.get("port") or port.get("portid")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _pick_http_port(ports: List[Dict[str, Any]]) -> Optional[int]:
    """Return the first port that looks like HTTP(S), or None."""
    for p in ports:
        num = _port_num(p)
        if num is None:
            continue
        if str(p.get("service", "")).lower() in _HTTP_SERVICES or num in _HTTP_PORTS:
            return num
    return None


def _http_url(host: str, port: int) -> str:
    scheme = "https" if port in _TLS_PORTS else "http"
    return f"{scheme}://{host}:{port}/"


@dataclass
class ProbeContext:
    """The three inputs BehavioralFingerprint.run consumes."""

    probe_fn: Callable[[int], ProbeResult]
    headers: Dict[str, str] = field(default_factory=dict)
    banners: List[str] = field(default_factory=list)


def build_probe_context(
    target: str,
    ports: List[Dict[str, Any]],
    *,
    http_get: Optional[HttpGet] = None,
    banner_grab: Optional[BannerGrab] = None,
    max_probes: int = _MAX_BANNER_PROBES,
    budget: float = _TOTAL_BUDGET,
    now_fn: Callable[[], float] = time.monotonic,
) -> ProbeContext:
    """Build a :class:`ProbeContext` for ``target`` from its open ``ports``.

    ``http_get`` and ``banner_grab`` default to live network calls but are
    injectable for tests. The timing ``probe_fn`` reuses ``banner_grab`` on the
    first open port so a slow-dripping tarpit surfaces as high latency.
    """
    http_get = http_get or _default_http_get
    banner_grab = banner_grab or _default_banner_grab

    # WAF headers: query the first HTTP(S) port, if any.
    headers: Dict[str, str] = {}
    http_port = _pick_http_port(ports)
    if http_port is not None:
        headers = http_get(_http_url(target, http_port))

    # Honeypot banners: one grab per open port, bounded by a probe cap and a
    # total time budget so a mass-open or slow target cannot stall the phase.
    banners: List[str] = []
    probes_done = 0
    budget_start = now_fn()
    for p in ports:
        if probes_done >= max_probes:
            break
        if now_fn() - budget_start > budget:
            break
        num = _port_num(p)
        if num is None:
            continue
        banner = banner_grab(target, num)
        probes_done += 1
        if banner:
            banners.append(banner)

    # Tarpit timing: measure connect+read latency on the first open port.
    probe_port = _port_num(ports[0]) if ports else None

    def probe_fn(_i: int) -> ProbeResult:
        if probe_port is None:
            return ProbeResult(latency=0.0)
        start = time.monotonic()
        banner = banner_grab(target, probe_port)
        return ProbeResult(latency=time.monotonic() - start, banner=banner, length=len(banner))

    return ProbeContext(probe_fn=probe_fn, headers=headers, banners=banners)
