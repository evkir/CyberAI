"""
Port service fingerprinter — enriches nmap port data
with banner grabbing and service version hints.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional

from cyberai.core.security.input_sanitizer import sanitize_banner

TIMEOUT = 3.0

# How long to wait for a service that speaks first. SSH, SMTP and FTP send
# their banner on connect, so this only has to cover the round trip. A service
# that has said nothing by then is one that waits to be asked.
PASSIVE_TIMEOUT = 1.0

HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"

# A name, a separator, then a dotted number: OpenSSH_9.6, Werkzeug/2.2.3,
# ProFTPD 1.3.5. The name is required so the number is a version of something.
_VERSION_RE = re.compile(r"[A-Za-z][A-Za-z0-9.+-]*[/_ ]v?(\d+\.\d+[A-Za-z0-9._-]*)")

BANNER_PROBES: Dict[str, bytes] = {
    "http": HTTP_PROBE,
    "ftp": b"",
    "smtp": b"",
    "ssh": b"",
    "default": b"",
}

SERVICE_SIGNATURES: List[Dict[str, Any]] = [
    {"pattern": b"SSH", "service": "ssh", "proto": "tcp"},
    {"pattern": b"HTTP", "service": "http", "proto": "tcp"},
    {"pattern": b"220", "service": "ftp/smtp", "proto": "tcp"},
    {"pattern": b"MySQL", "service": "mysql", "proto": "tcp"},
    {"pattern": b"Redis", "service": "redis", "proto": "tcp"},
    {"pattern": b"Mongo", "service": "mongodb", "proto": "tcp"},
    {"pattern": b"SMB", "service": "smb", "proto": "tcp"},
    {"pattern": b"RFB", "service": "vnc", "proto": "tcp"},
]

WELL_KNOWN_PORTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
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
    banner = _grab_banner(host, port, service_hint)
    detected = _detect_service(banner, port)
    raw = banner[:256].decode("utf-8", errors="replace") if banner else ""

    return {
        "port": port,
        "service": detected or service_hint or WELL_KNOWN_PORTS.get(port, "unknown"),
        "banner": sanitize_banner(raw),
        "version": _extract_version(banner),
    }


def fingerprint_ports(
    host: str,
    ports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Enrich nmap port dicts with banner data without overwriting nmap.

    Only ports nmap left without a ``product`` are probed: a port -sV already
    identified needs nothing from a banner grab, and paying an extra connect
    for it would change the network profile for no data.

    The merge is field by field on purpose. ``{**p, **fp}`` pushes this
    module's fallbacks over nmap's measured ``service`` and ``version``, and
    those two fields are what ``intel/version_match`` reads to decide whether
    a CVE covers the running build.

    A port this function cannot probe is returned unchanged rather than
    dropped: the caller writes the returned list back into the knowledge
    base, so a skipped port would disappear from the scan result entirely.
    """
    results = []
    for p in ports:
        port_num = p.get("port") or p.get("portid")
        if not port_num:
            results.append(p)
            continue
        if (p.get("product") or "").strip():
            results.append(p)
            continue
        try:
            fp = fingerprint_port(
                host,
                int(port_num),
                service_hint=p.get("service", ""),
            )
        except Exception:
            results.append(p)
            continue
        enriched = dict(p)
        if _service_is_unmeasured(enriched):
            enriched["service"] = fp["service"]
        if not (enriched.get("version") or "").strip():
            enriched["version"] = fp["version"]
        if fp["banner"]:
            enriched["banner"] = fp["banner"]
        results.append(enriched)
    return results


def _service_is_unmeasured(port: Dict[str, Any]) -> bool:
    """Whether nmap's service name for this port is a guess rather than a read.

    Two cases qualify. An empty name is nothing to overwrite. A name nmap
    itself marks ``method="table"`` is the port number looked up in
    nmap-services: port 3000 is called "ppp" there whatever is listening.

    A missing method is not treated as a guess. The attribute is absent from
    older scan output, and a default of "overwrite" would answer "measured"
    with "measured, and wrong" -- destroying exactly the field the CVE version
    gate reads.
    """
    if not (port.get("service") or "").strip():
        return True
    return (port.get("service_method") or "").strip() == "table"


def _grab_banner(host: str, port: int, hint: str) -> bytes:
    """Connect, listen, and ask if nothing was said.

    The probe used to be chosen from nmap's service name alone, which is the
    one thing this function cannot trust: it only runs on ports -sV failed to
    identify, where that name is a lookup of the port number in nmap-services
    rather than a measurement. A web server on port 3000 is called "ppp"
    there, so it got the empty probe, said nothing because nothing had asked
    it anything, and cost the full timeout to learn nothing.

    So the hint only decides whether to speak first. A service that talks on
    connect is heard out; one that stays silent is sent an HTTP request,
    because a port that waits to be asked is usually waiting to be asked
    that. Both phases share the one connection the probe already paid for.
    """
    probe = BANNER_PROBES.get(hint, BANNER_PROBES["default"])
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            if probe:
                sock.sendall(probe)
                return sock.recv(1024)

            sock.settimeout(PASSIVE_TIMEOUT)
            try:
                banner = sock.recv(1024)
            except TimeoutError:
                banner = b""
            if banner:
                return banner

            # Silence is not absence: the socket is still usable after a read
            # timeout, so the second phase costs no new connection.
            sock.settimeout(TIMEOUT)
            sock.sendall(HTTP_PROBE)
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
    """Pull a service version out of a banner, or report that there is none.

    The old implementation returned the first line containing any digit at
    all, which on an HTTP response is the status line: a live scan recorded
    ``version="HTTP/1.1 200 OK"`` for a web server. ``version`` is what
    ``intel/version_match`` compares against CPE ranges, so a field that
    answers "measured" with something that was never a version is worse than
    one that stays empty.

    An HTTP banner is read only from its ``Server`` header. The protocol
    version in the status line describes the conversation, not the software,
    and ``HTTP/1.1`` would otherwise parse as a perfectly plausible 1.1.
    """
    if not banner:
        return ""
    # No try around the decode: errors="replace" is total over bytes and the
    # empty case is already gone, so the guard that sat here could not fire on
    # any input. It could only have swallowed a TypeError from a caller
    # passing something that is not bytes -- hiding the one bug it might have
    # caught.
    text = banner[:512].decode("utf-8", errors="replace")

    if text.lstrip().upper().startswith("HTTP/"):
        for line in text.splitlines():
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() == "server":
                return _version_token(value)
        return ""
    return _version_token(text)


def _version_token(text: str) -> str:
    """The first dotted version number in ``text``, attached to a name.

    Requires a dot: a bare integer in a banner is as likely to be a status
    code, a port or a year. Requires a preceding name so that a version is
    read from ``OpenSSH_9.6`` or ``Werkzeug/2.2.3`` rather than from any
    number that happens to be punctuated.
    """
    match = _VERSION_RE.search(text)
    return match.group(1)[:40] if match else ""
