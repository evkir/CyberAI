"""Tests for the bench success-criteria evaluator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

from cyberai.bench.evaluator import (
    cmdi_solved_from_evidence,
    evaluate,
    probe_cmdi,
    ssrf_solved_from_evidence,
    probe_for,
    probe_sqli,
    probe_ssrf,
    probe_traversal,
    sqli_solved_from_evidence,
    traversal_solved_from_evidence,
)
from cyberai.bench.targets import LOCAL_SUITE, VulnClass, VulnTarget


def _target(vc: VulnClass) -> VulnTarget:
    return next(t for t in LOCAL_SUITE if t.vuln_class is vc)


def test_sqli_marker_detection():
    assert sqli_solved_from_evidence('{"flag": "FLAG{sqli-auth-bypass}"}') is True
    assert sqli_solved_from_evidence('{"status": "denied"}') is False


def test_cmdi_requires_injected_marker():
    assert cmdi_solved_from_evidence("uid=0(root) TOKEN42", "TOKEN42") is True
    assert cmdi_solved_from_evidence("64 bytes from 127.0.0.1", "TOKEN42") is False
    assert cmdi_solved_from_evidence("anything", "") is False


def test_traversal_requires_secret_token():
    assert traversal_solved_from_evidence("root:x:0:0:secretz", "secretz") is True
    assert traversal_solved_from_evidence("<html>index</html>", "secretz") is False


def test_evaluate_dispatch_per_class():
    assert evaluate(_target(VulnClass.SQLI), "FLAG{sqli-auth-bypass}") is True
    assert evaluate(_target(VulnClass.COMMAND_INJECTION), "x TOK", marker="TOK") is True
    assert evaluate(_target(VulnClass.PATH_TRAVERSAL), "data SEC", marker="SEC") is True


def test_evaluate_unknown_class_is_unsolved():
    t = VulnTarget(
        id="z",
        name="z",
        vuln_class=VulnClass.SSRF,
        cwe="CWE-918",
        port=9009,
        app="ssrf",
        success_signal="oob",
    )
    assert evaluate(t, "anything") is False


def test_probe_sqli_mocked_success():
    resp = MagicMock(text='{"flag": "FLAG{sqli-auth-bypass}"}')
    client = MagicMock()
    client.__enter__.return_value.post.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_sqli("http://localhost:8801") is True


def test_probe_sqli_mocked_http_error():
    import httpx

    client = MagicMock()
    client.__enter__.return_value.post.side_effect = httpx.ConnectError("down")
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_sqli("http://localhost:8801") is False


def test_probe_cmdi_mocked_success():
    resp = MagicMock(text='{"output": "PING 127.0.0.1 ...\\n20571\\n"}')
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_cmdi("http://localhost:8802") is True


def test_probe_cmdi_rejects_reflected_payload():
    """A hardened target echoing the raw request must never count as solved."""
    resp = MagicMock(text="404 not found: 127.0.0.1; echo $((6857*3))")
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_cmdi("http://localhost:8802") is False


def test_probe_cmdi_mocked_http_error():
    import httpx

    client = MagicMock()
    client.__enter__.return_value.get.side_effect = httpx.ConnectError("down")
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_cmdi("http://localhost:8802") is False


def test_probe_traversal_mocked_success():
    resp = MagicMock(text="FLAG{path-traversal-file-read}")
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_traversal("http://localhost:8803") is True


def test_probe_traversal_rejects_reflected_filename():
    """Echoing the requested path back must never count as a file read."""
    resp = MagicMock(text="404 not found: ../../../../etc/bench_flag")
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_traversal("http://localhost:8803") is False


def test_probe_traversal_mocked_http_error():
    import httpx

    client = MagicMock()
    client.__enter__.return_value.get.side_effect = httpx.ConnectError("down")
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_traversal("http://localhost:8803") is False


def _ssrf_target() -> VulnTarget:
    return VulnTarget(
        id="t-ssrf",
        name="ssrf",
        vuln_class=VulnClass.SSRF,
        cwe="CWE-918",
        port=9999,
        app="ssrf_fetch",
        success_signal="collector recorded a callback carrying the run nonce",
    )


def test_ssrf_nonce_detection():
    assert ssrf_solved_from_evidence("GET /c/N0NCE-7 from 172.17.0.2", "N0NCE-7") is True
    assert ssrf_solved_from_evidence("GET /c/other from 172.17.0.2", "N0NCE-7") is False


def test_ssrf_empty_nonce_is_never_solved():
    # No constant fallback for this class: an empty nonce must not match a
    # collector record that happens to be non-empty.
    assert ssrf_solved_from_evidence("GET /c/anything", "") is False


def test_evaluate_dispatches_ssrf_to_the_nonce_check():
    target = _ssrf_target()
    assert evaluate(target, "GET /c/AB12 from 172.17.0.2", marker="AB12") is True
    assert evaluate(target, "GET /c/AB12 from 172.17.0.2", marker="ZZ99") is False


def test_evaluate_ssrf_without_a_marker_is_unsolved():
    # The dispatcher must not substitute a constant here the way CMDi and
    # traversal do; without a nonce there is nothing to prove.
    assert evaluate(_ssrf_target(), "GET /c/AB12 from 172.17.0.2") is False


def test_probe_ssrf_against_the_live_blind_target():
    """The real app, in process: proof arrives out of band or not at all.

    Asserted against the app itself rather than a mock, because what is being
    checked is that the target issues an outbound request the probe can catch.
    A mocked httpx call would prove only that the probe formats a URL.
    """
    import threading
    from http.server import HTTPServer

    from cyberai.bench.apps import ssrf_fetch

    server = HTTPServer(("127.0.0.1", 0), ssrf_fetch.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        assert probe_ssrf(base) is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_the_blind_target_reply_carries_no_trace_of_the_outcome():
    """If the reply differed by outcome the target would not be blind, and the
    response-reading walk would confirm it -- which is the case this whole
    target exists to exclude."""
    import threading
    from http.server import HTTPServer

    import httpx

    from cyberai.bench.apps import ssrf_fetch

    server = HTTPServer(("127.0.0.1", 0), ssrf_fetch.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with httpx.Client(timeout=10) as client:
            reachable = client.get(f"{base}/fetch", params={"url": base})
            refused = client.get(f"{base}/fetch", params={"url": "http://127.0.0.1:1/x"})
            absent = client.get(f"{base}/fetch")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert reachable.text == refused.text == absent.text
    assert reachable.status_code == refused.status_code == absent.status_code


def test_probe_ssrf_ignores_a_callback_that_is_not_ours():
    """A callback is proof only if it carries this call's nonce.

    A target may reach the collector for reasons of its own -- a health check,
    a retry of someone else's URL, an unrelated crawler. Counting any arrival
    would score that as an exploited SSRF, and on a shared collector two runs
    would start confirming each other. The stand-in target here does issue an
    outbound request, just not the one it was handed.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse
    import urllib.request

    class _NoisyHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            params = parse_qs(urlparse(self.path).query)
            given = (params.get("url") or [""])[0]
            if given:
                # Same collector, different path: arrival without our nonce.
                bits = urlparse(given)
                try:
                    urllib.request.urlopen(
                        f"http://{bits.netloc}/unrelated-traffic", timeout=5
                    ).read()
                except Exception:
                    pass
            body = b'{"status": "accepted"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), _NoisyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert probe_ssrf(f"http://127.0.0.1:{server.server_port}") is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_probe_for_routes_the_ssrf_class_to_the_live_probe():
    """The dispatch branch, not the probe: reaching probe_ssrf only by direct
    call would leave the path the engine actually takes unexercised -- the
    shape that has silently dropped fields here before."""
    import threading
    from http.server import HTTPServer

    from cyberai.bench.apps import ssrf_fetch

    target = _ssrf_target()
    server = HTTPServer(("127.0.0.1", 0), ssrf_fetch.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        assert probe_for(target, base) is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
