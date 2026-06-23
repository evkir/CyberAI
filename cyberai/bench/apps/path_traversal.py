"""Vulnerable target: path traversal file read (CWE-22). Benchmark use only."""

from __future__ import annotations

import os

from flask import Flask, Response, request

app = Flask(__name__)
WEB_ROOT = "/srv/www"


@app.route("/file")
def serve_file():
    name = request.args.get("name", "index.html")
    # INTENTIONALLY VULNERABLE: no normalization, join allows ../ escape.
    path = os.path.join(WEB_ROOT, name)
    try:
        with open(path) as fh:
            return Response(fh.read(), mimetype="text/plain")
    except OSError:
        return {"error": "not found"}, 404


@app.route("/")
def index():
    return {"service": "path_traversal", "hint": "GET /file?name=", "secret": "/etc/bench_flag"}
