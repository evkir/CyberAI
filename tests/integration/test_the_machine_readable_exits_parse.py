"""The machine-readable exits of `cyberai mcp-scan` must survive json.loads.

Both --json and --report-json wrote their payload to stdout, and so did every
log line, so the bytes a consumer received began with the rich log timestamp
and could not be parsed at all. Three CLI tests were green over it because
they asserted substrings: a key name is present in the text whether or not any
parser will accept the document around it.

The scan runs in a real subprocess against the real server, and stdout is read
the way a consumer reads it. A mocked agent emits no log lines, so a mocked run
has clean stdout whether the routing is fixed or not; and the in-process runner
merges the two streams, so neither shape can tell the fix from its absence.
"""

from __future__ import annotations

import json
import subprocess
import sys

LAUNCH = f"{sys.executable} -m cyberai.mcp.server"


def _scan(*flags: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "cyberai", "mcp-scan", LAUNCH, *flags],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:])
    return proc


def test_the_json_exit_parses():
    proc = _scan("--json")
    parsed = json.loads(proc.stdout)
    assert parsed["connected"] is True
    assert parsed["probe"]["server_name"] == "cyberai"


def test_the_report_json_exit_parses():
    proc = _scan("--report-json")
    parsed = json.loads(proc.stdout)
    assert parsed["connected"] is True
    assert "risks" in parsed


def test_the_log_goes_to_the_other_stream():
    """The lines that used to prefix the payload must still be emitted."""
    proc = _scan("--json")
    assert "MCP scan target" in proc.stderr
    assert "MCP scan target" not in proc.stdout
