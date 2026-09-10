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

`detector eval --json` was measured clean before this file grew to cover it, so
that half guards a working exit rather than fixing a broken one. Four existing
tests already parse its output, but all of them go through the in-process
runner, which merges stdout and stderr: none of them would notice a log line
moving into the payload. Reading the two streams apart is what is added here.
Its help text documents redirecting stdout into a baseline file, which makes
the promise a public one.

The inventory below fails when a fourth machine-readable exit appears, so a new
one cannot ship without a parse test of its own.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import click

from cyberai.__main__ import cli

LAUNCH = f"{sys.executable} -m cyberai.mcp.server"
# Rule: a repo path in a test comes from __file__, never from the shell's cwd.
REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "tests" / "corpus"


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


def test_the_detector_eval_json_exit_parses():
    """Its --help documents `--json > baseline.json`; that promise is the test."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "cyberai",
            "detector",
            "eval",
            "--corpus",
            str(CORPUS),
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:])
    parsed = json.loads(proc.stdout)
    assert "overall" in parsed
    assert parsed["corpus"] == str(CORPUS)


def _machine_readable_flags() -> set[tuple[str, str]]:
    """Every command that offers to emit a machine-readable document."""

    def walk(group, prefix=()):
        for name, command in sorted(getattr(group, "commands", {}).items()):
            path = prefix + (name,)
            if isinstance(command, click.Group):
                yield from walk(command, path)
                continue
            for param in command.params:
                if isinstance(param, click.Option):
                    for opt in param.opts:
                        if "json" in opt:
                            yield " ".join(path), opt

    return set(walk(cli))


def test_the_inventory_of_machine_readable_exits_is_the_one_measured():
    """A fourth exit must not ship without a parse test; this is where it trips."""
    assert _machine_readable_flags() == {
        ("detector eval", "--json"),
        ("mcp-scan", "--json"),
        ("mcp-scan", "--report-json"),
    }
