"""Vulnerable target: blind SSRF via URL fetch (CWE-918). Benchmark use only.

Served inside an ephemeral benchmark container; never expose this publicly.

Deliberately blind: /fetch answers the same body, status and length whether
the outbound request succeeded, failed or was never made. Nothing about the
result reaches the caller, so response-reading exploitation cannot confirm
this target at all -- only an out-of-band collector can. That is the whole
point of the target: it is the case the main path is documented to drop.
"""

from __future__ import annotations

import urllib.request

try:  # package import (tests, local tooling)
    from cyberai.bench.apps._server import BenchHandler, serve
except ImportError:  # standalone run inside the bench container
    from _server import BenchHandler, serve

PORT = 8804
# The server is single-threaded, so a hanging fetch would stop the target from
# answering anything else. A blocked request must fail fast, not wedge the app.
FETCH_TIMEOUT = 5
# One reply for every outcome. Any variation here -- a status, a length, an
# error string -- would make the vector visible to a response-reading walk.
_CONSTANT_REPLY = {"status": "accepted"}


def _fetch(h: BenchHandler) -> None:
    url = h.query.get("url", "")
    if url:
        # INTENTIONALLY VULNERABLE: a user-supplied URL is fetched unchecked.
        try:
            urllib.request.urlopen(url, timeout=FETCH_TIMEOUT).read()  # noqa: S310
        except Exception:  # noqa: BLE001 - outcome must not reach the caller
            pass
    h.respond(_CONSTANT_REPLY)


def _index(h: BenchHandler) -> None:
    h.respond({"service": "ssrf_fetch", "hint": "GET /fetch?url="})


class Handler(BenchHandler):
    routes = {("GET", "/fetch"): _fetch, ("GET", "/"): _index}


if __name__ == "__main__":
    serve(Handler, PORT)
