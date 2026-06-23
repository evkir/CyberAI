"""Vulnerable target: OS command injection (CWE-78). Benchmark use only."""

from __future__ import annotations

import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # INTENTIONALLY VULNERABLE: user input flows into a shell command.
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5)  # noqa: S602
    return {"output": out.stdout + out.stderr}


@app.route("/")
def index():
    return {"service": "cmdi_ping", "hint": "GET /ping?host=", "flag_file": "/flag.txt"}
