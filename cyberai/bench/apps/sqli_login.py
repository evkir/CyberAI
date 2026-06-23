"""Vulnerable target: SQL injection auth bypass (CWE-89). Benchmark use only."""

from __future__ import annotations

import sqlite3

from flask import Flask, request

app = Flask(__name__)


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 's3cr3t-flag-7f3a')")
    return conn


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    # INTENTIONALLY VULNERABLE: string-built query, no parameterization.
    query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{pw}'"  # noqa: S608
    row = _db().execute(query).fetchone()
    if row:
        return {"status": "ok", "flag": "FLAG{sqli-auth-bypass}", "user": row[1]}
    return {"status": "denied"}, 401


@app.route("/")
def index():
    return {"service": "sqli_login", "hint": "POST /login username,password"}
