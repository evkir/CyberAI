"""Minimal stdlib HTTP scaffolding shared by the bench targets.

Deliberately stdlib-only: the bench containers run a bare `python:*-slim`
image with the apps mounted read-only, so no dependency may be installed at
run time (keeps runs offline-capable and fast).
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict
from urllib.parse import parse_qs, urlparse


def _query(path: str) -> Dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(path).query).items()}


class BenchHandler(BaseHTTPRequestHandler):
    """Routes are supplied by each app as {(method, path): handler}."""

    routes: Dict[tuple, Callable[["BenchHandler"], Any]] = {}

    def log_message(self, fmt: str, *args: Any) -> None:  # keep output quiet
        pass

    def _dispatch(self, method: str) -> None:
        route = urlparse(self.path).path
        handler = self.routes.get((method, route))
        if handler is None:
            self.respond({"error": "not found"}, status=404)
            return
        handler(self)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    # -- helpers used by the app modules -------------------------------
    @property
    def query(self) -> Dict[str, str]:
        return _query(self.path)

    def form(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def respond(self, payload: Any, status: int = 200, content_type: str = "") -> None:
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload).encode()
            content_type = content_type or "application/json"
        else:
            body = str(payload).encode()
            content_type = content_type or "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler_cls: type[BenchHandler], default_port: int) -> None:
    """Bind 0.0.0.0 so the port publishes out of the container."""
    port = int(sys.argv[1]) if len(sys.argv) > 1 else default_port
    HTTPServer(("0.0.0.0", port), handler_cls).serve_forever()
