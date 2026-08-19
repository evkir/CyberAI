"""
Native TLS probe tests against a real local TLS server.

No mock stands in for the handshake here. Certificates are generated with
controlled dates so the expired and untrusted paths are exercised for real,
and the server is a plain socket on localhost, so the suite needs no network.
"""

import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cyberai.agents.recon.tls_probe import probe_tls
from cyberai.agents.recon.tls_tool import TLSTool, _weak_tokens

ISSUER_ORG = "CyberAI Test CA"


def _make_cert(tmp_path, not_after_days: int, name: str = "localhost"):
    """Write a self-signed cert expiring in ``not_after_days`` (negative = past)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ISSUER_ORG),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / f"{name}-{not_after_days}.pem"
    key_path = tmp_path / f"{name}-{not_after_days}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class _TLSServer:
    """One-shot TLS listener on 127.0.0.1, serving a given cert."""

    def __init__(self, cert_path: str, key_path: str):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.close()

    def close(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture
def tls_server(tmp_path):
    servers = []

    def _start(not_after_days: int):
        cert, key = _make_cert(tmp_path, not_after_days)
        server = _TLSServer(cert, key)
        servers.append(server)
        return server.port

    yield _start

    for server in servers:
        server.close()


class TestProbeAgainstRealServer:
    def test_expired_cert_reports_negative_days(self, tls_server):
        port = tls_server(-35)
        result = probe_tls("localhost", port=port, timeout=5)

        assert result.reachable
        assert not result.cert_valid
        assert result.cert_expiry_days is not None
        assert result.cert_expiry_days < 0
        assert result.is_expired

    def test_untrusted_but_current_cert_is_not_expired(self, tls_server):
        """Self-signed and expired are different problems."""
        port = tls_server(200)
        result = probe_tls("localhost", port=port, timeout=5)

        assert not result.cert_valid
        assert result.cert_expiry_days > 0
        assert not result.is_expired
        assert not result.is_expiring_soon

    def test_untrusted_cert_still_yields_issuer(self, tls_server):
        """The second handshake recovers what verification refused to parse."""
        port = tls_server(200)
        result = probe_tls("localhost", port=port, timeout=5)

        assert result.cert_issuer == ISSUER_ORG
        assert result.cert_subject == "localhost"

    def test_handshake_details_are_reported(self, tls_server):
        port = tls_server(200)
        result = probe_tls("localhost", port=port, timeout=5)

        assert result.tls_version.startswith("TLSv1.")
        assert result.cipher

    def test_expiring_soon_window(self, tls_server):
        port = tls_server(10)
        result = probe_tls("localhost", port=port, timeout=5)

        assert result.is_expiring_soon
        assert not result.is_expired


class TestUnreachableTarget:
    def test_closed_port_is_not_expired(self):
        """An unmeasured host must never look like an expired certificate."""
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        result = probe_tls("127.0.0.1", port=port, timeout=3)

        assert not result.reachable
        assert result.cert_expiry_days is None
        assert not result.is_expired
        assert result.error


class TestToolOverRealServer:
    def test_expired_cert_is_critical_and_carries_the_mapper_key(self, tls_server):
        port = tls_server(-35)
        out = TLSTool().run(f"localhost:{port}")

        issues = {f["issue"]: f for f in out["findings"]}
        assert issues["Certificate expired"]["severity"] == "CRITICAL"
        assert "cert_expired" in issues["Certificate expired"]["detail"]

    def test_untrusted_cert_is_medium_not_critical(self, tls_server):
        port = tls_server(200)
        out = TLSTool().run(f"localhost:{port}")

        severities = {f["issue"]: f["severity"] for f in out["findings"]}
        assert severities["Certificate not trusted"] == "MEDIUM"
        assert "Certificate expired" not in severities

    def test_unreachable_target_reports_error_and_no_findings(self):
        out = TLSTool().run("127.0.0.1:1")

        assert "error" in out
        assert out["findings"] == []


class TestWeakCipherTokens:
    def test_rc4_token_is_the_mapper_key(self):
        assert _weak_tokens("ECDHE-RSA-RC4-SHA") == ["RC4"]

    def test_null_cipher_maps_to_mapper_key(self):
        assert "NULL_cipher" in _weak_tokens("ECDHE-RSA-NULL-SHA")

    def test_modern_suite_has_no_weak_tokens(self):
        assert _weak_tokens("TLS_AES_256_GCM_SHA384") == []
