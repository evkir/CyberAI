"""
Native TLS probe.

Opens a real TLS handshake against the target and reports what the server
actually presented: protocol version, negotiated cipher, ALPN, and the
certificate's own expiry.

Two handshakes, deliberately:

1. A verifying context, exactly as a browser would. If it succeeds the chain
   is trusted and ``getpeercert()`` returns the parsed dict, expiry included.
2. If verification fails, a second handshake without verification recovers the
   certificate anyway, so an expired or self-signed cert can still be reported
   with its real dates instead of vanishing behind the exception.

``cert_expiry_days`` is ``None`` when it could not be measured, never 0.
A zero default is indistinguishable from "expires today" and would turn every
unmeasured host into a CRITICAL finding.
"""

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509

logger = logging.getLogger("cyberai.recon.tls_probe")

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10


@dataclass
class TLSProbeResult:
    """What a single handshake against one host revealed."""

    domain: str
    reachable: bool = False
    tls_version: str = ""
    cipher: str = ""
    alpn: list[str] = field(default_factory=list)
    cert_valid: bool = False
    cert_error: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry_days: Optional[int] = None
    error: str = ""

    @property
    def is_expired(self) -> bool:
        """True only when expiry was measured and has passed."""
        return self.cert_expiry_days is not None and self.cert_expiry_days < 0

    @property
    def is_expiring_soon(self) -> bool:
        """True only when expiry was measured and falls inside 30 days."""
        return self.cert_expiry_days is not None and 0 <= self.cert_expiry_days <= 30


def _days_until(expiry: datetime) -> int:
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return (expiry - datetime.now(timezone.utc)).days


def _verifying_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx


def _permissive_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx


def _fill_from_socket(result: TLSProbeResult, sock: ssl.SSLSocket) -> None:
    result.reachable = True
    result.tls_version = sock.version() or ""
    cipher = sock.cipher()
    result.cipher = cipher[0] if cipher else ""
    negotiated = sock.selected_alpn_protocol()
    result.alpn = [negotiated] if negotiated else []


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""


def _probe_untrusted(result: TLSProbeResult, domain: str, port: int, timeout: int) -> None:
    """Recover the certificate a verifying handshake refused to accept."""
    ctx = _permissive_context()
    with socket.create_connection((domain, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=domain) as sock:
            _fill_from_socket(result, sock)
            der = sock.getpeercert(binary_form=True)

    if not der:
        return

    cert = x509.load_der_x509_certificate(der)
    result.cert_subject = _name_attr(cert.subject, x509.oid.NameOID.COMMON_NAME)
    result.cert_issuer = _name_attr(cert.issuer, x509.oid.NameOID.ORGANIZATION_NAME)
    result.cert_expiry_days = _days_until(cert.not_valid_after_utc)


def probe_tls(
    domain: str,
    port: int = DEFAULT_PORT,
    timeout: int = DEFAULT_TIMEOUT,
) -> TLSProbeResult:
    """Handshake with ``domain`` and report what the server presented."""
    result = TLSProbeResult(domain=domain)

    try:
        ctx = _verifying_context()
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as sock:
                _fill_from_socket(result, sock)
                peer = sock.getpeercert() or {}
                # Verification succeeding is not the same as having parsed a
                # certificate. Asserting validity before looking at what came
                # back is how the previous TLS source reported cert_valid=True
                # for an expired certificate.
                result.cert_valid = bool(peer)
                subject = dict(x[0] for x in peer.get("subject", []))
                issuer = dict(x[0] for x in peer.get("issuer", []))
                result.cert_subject = subject.get("commonName", "")
                result.cert_issuer = issuer.get("organizationName", "")
                not_after = peer.get("notAfter", "")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        result.cert_expiry_days = _days_until(expiry)
                    except ValueError:
                        # A date we cannot read leaves expiry unmeasured,
                        # which is what None means. It must not abort the
                        # probe: the version and cipher are already known
                        # and are worth reporting.
                        logger.warning(f"{domain}: unreadable certificate expiry {not_after!r}")
        return result
    except ssl.SSLCertVerificationError as exc:
        result.cert_error = exc.verify_message or str(exc.reason)
    except (ssl.SSLError, OSError) as exc:
        result.error = str(exc)
        return result

    try:
        _probe_untrusted(result, domain, port, timeout)
    except (ssl.SSLError, OSError, ValueError) as exc:
        result.error = str(exc)

    return result
