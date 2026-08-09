"""Negative controls: no probe may report a solve against a hardened target.

Every live probe in `cyberai.bench.evaluator` searches a response for a success
signal. The failure mode this file exists to prevent is a probe that searches
for a token it sent itself: a benign target merely reflecting request input --
a 404 quoting the filename, an error echoing the host parameter -- would then
be scored as exploited, and pass@1 would overstate the engine's capability.

Two hardened servers stand in for that case: one that never reflects input, and
one that echoes every parameter it receives. Neither is exploitable. Every
probe must report unsolved against both.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from cyberai.bench.evaluator import probe_cmdi, probe_sqli, probe_ssrf, probe_traversal


class _SilentHandler(BaseHTTPRequestHandler):
    """Hardened target: answers, but never reflects request input."""

    def log_message(self, *args):  # keep pytest output clean
        pass

    def do_GET(self):
        self._respond(b"access denied")

    def do_POST(self):
        self._respond(b'{"status": "denied"}')

    def _respond(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _EchoHandler(_SilentHandler):
    """Hardened target that echoes request input back -- still not exploitable."""

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        echoed = " ".join(value for values in params.values() for value in values)
        self._respond(f"404 not found: {echoed}".encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        self._respond(f"invalid credentials: {body}".encode())


def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def silent_target():
    yield from _serve(_SilentHandler)


@pytest.fixture
def echo_target():
    yield from _serve(_EchoHandler)


@pytest.mark.parametrize(
    "probe",
    [probe_sqli, probe_cmdi, probe_traversal, probe_ssrf],
    ids=["sqli", "cmdi", "traversal", "ssrf"],
)
def test_no_probe_solves_a_silent_hardened_target(probe, silent_target):
    assert probe(silent_target) is False


@pytest.mark.parametrize(
    "probe",
    [probe_sqli, probe_cmdi, probe_traversal, probe_ssrf],
    ids=["sqli", "cmdi", "traversal", "ssrf"],
)
def test_no_probe_solves_a_reflecting_hardened_target(probe, echo_target):
    assert probe(echo_target) is False
