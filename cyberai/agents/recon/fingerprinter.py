"""
Port service fingerprinter — enriches nmap port data
with banner grabbing and service version hints.
"""
from __future__ import annotations
import socket
from typing import Any, Dict, List, Optional

TIMEOUT = 3.0

BANNER_PROBES: Dict[str, bytes] = {
    "http":    b"HEAD / HTTP/1.0\r\n\r\n",
    "ftp":     b"",
    "smtp":    b"",
    "ssh":     b"",
    "default": b"",
}

SERVICE_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": b"SSH",              "service": "ssh",        "proto": "tcp"},
    {"pattern": b"HTTP",             "service": "http",       "proto": "tcp"},
    {"pattern": b"220",              "service": "ftp/smtp",   "proto": "tcp"},
    {"pattern": b"MySQL",            "service": "mysql",      "proto": "tcp"},
    {"pattern": b"Redis",            "service": "redis",      "proto": "tcp"},
    {"pattern": b"Mongo",            "service": "mongodb",    "proto": "tcp"},
    {"pattern": b"SMB",              "service": "smb",        "proto": "tcp"},
    {"pattern": b"RFB",              "service": "vnc",        "proto": "tcp"},
]

WELL_KNOWN_PORTS: Dict[int, str] = {
    21:   "ftp",    22:   "ssh",     23:  "telnet",
    25:   "smtp",   53:   "dns",     80:  "http",
    110:  "pop3",   143:  "imap",    443: "https",
    445:  "smb",    3306: "mysql",   3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt",  27017: "mongodb",
}


def fingerprint_port(
    host: str,
    port: int,
    service_hint: str = "",
) -> Dict[str, Any]:
    """
    Attempt banner grab on host:port.
    Returns enriched port info dict.
    """
    banner   = _grab_banner(host, port, service_hint)
    detected = _detect_service(banner, port)

    return {
        "port":    port,
        "host":    host,
        "service": detected or service_hint or WELL_KNOWN_PORTS.get(port, "unknown"),
        "banner":  banner[:256].decode("utf-8", errors="replace") if banner else "",
        "version": _extract_version(banner),
    }


def fingerprint_ports(
    host: str,
    ports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Fingerprint a list of port dicts from nmap output."""
    results = []
    for p in ports:
        port_num = p.get("port") or p.get("portid")
        if not port_num:
            continue
        try:
            fp = fingerprint_port(
                host,
                int(port_num),
                service_hint=p.get("service", ""),
            )
            results.append({**p, **fp})
        except Exception:
            results.append(p)
    return results


def _grab_banner(host: str, port: int, hint: str) -> bytes:
    """Connect and grab service banner."""
    probe = BANNER_PROBES.get(hint, BANNER_PROBES["default"])
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            if probe:
                sock.sendall(probe)
            return sock.recv(1024)
    except Exception:
        return b""


def _detect_service(banner: bytes, port: int) -> Optional[str]:
    """Match banner against known signatures."""
    if not banner:
        return WELL_KNOWN_PORTS.get(port)
    for sig in SERVICE_SIGNATURES:
        if sig["pattern"] in banner:
            return sig["service"]
    return WELL_KNOWN_PORTS.get(port)


def _extract_version(banner: bytes) -> str:
    """Best-effort version string extraction from banner."""
    if not banner:
        return ""
    try:
        text = banner[:128].decode("utf-8", errors="replace")
        for line in text.splitlines():
            if any(c.isdigit() for c in line):
                return line.strip()[:80]
    except Exception:
        pass
    return ""
