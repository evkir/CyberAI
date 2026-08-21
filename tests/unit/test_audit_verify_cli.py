"""`cyberai audit-verify` is the only consumer of signature verification.

The signing tests in test_audit_signing.py call verify_trail directly. That
leaves the command itself — its exit code, its output, and the report
formatting it triggers — unexercised, which is how a verification tool ships
broken while its library passes. These tests drive the CLI.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.cli.audit_verify import verify_trail
from cyberai.core.logger import AuditLogger


@pytest.fixture
def trail(tmp_path: Path) -> Path:
    audit = AuditLogger(session_id="cli", output_dir=str(tmp_path))
    audit.agent_action("recon", "nmap_scan", {"target": "10.0.0.1"})
    audit.finding("recon", "Open SSH", "LOW")
    return tmp_path / "audit_cli.jsonl"


def _rewrite(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in events))


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_an_intact_trail_exits_zero(trail: Path):
    result = CliRunner().invoke(cli, ["audit-verify", str(trail)])
    assert result.exit_code == 0, result.output
    assert "2 verified" in result.output


def test_a_tampered_trail_exits_nonzero_and_names_the_line(trail: Path):
    """The exit code is the point: this command is meant to gate a pipeline."""
    events = _events(trail)
    events[0]["data"]["target"] = "8.8.8.8"
    _rewrite(trail, events)

    result = CliRunner().invoke(cli, ["audit-verify", str(trail)])
    assert result.exit_code == 1, result.output
    assert "tampered lines: 1" in result.output


def test_a_null_signature_is_a_mismatch_not_a_crash(trail: Path):
    """sig present but not a string reaches compare_digest, which rejects bytes.

    verify_trail only checks that the key exists, so a forged line carrying
    `"sig": null` gets past that check. Without the isinstance guard in
    SessionSigner.verify this raises TypeError and the whole file goes
    unverified — a crash an attacker can trigger by editing one line.
    """
    events = _events(trail)
    events[1]["sig"] = None
    _rewrite(trail, events)

    report = verify_trail(str(trail))
    assert report.tampered == [2], report.summary()

    result = CliRunner().invoke(cli, ["audit-verify", str(trail)])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_an_unparsable_line_is_reported_as_unreadable(trail: Path):
    """A truncated write is not the same finding as an edited field.

    The logger's FileHandler already terminates every line, so the appended
    text lands on line 3 without a leading newline of its own.
    """
    assert trail.read_text().endswith("\n")
    trail.write_text(trail.read_text() + "{not json at all")

    result = CliRunner().invoke(cli, ["audit-verify", str(trail)])
    assert result.exit_code == 1
    assert "unreadable lines: 3" in result.output
    assert "tampered lines" not in result.output


def test_blank_lines_are_not_counted_as_anything(trail: Path):
    """A trailing newline is normal file hygiene, not a verification failure."""
    trail.write_text(trail.read_text() + "\n\n")

    report = verify_trail(str(trail))
    assert report.verified == 2
    assert report.clean is True


def test_the_summary_counts_every_category(tmp_path: Path):
    """Read from the command's own output, so the format is what a user sees."""
    path = tmp_path / "mixed.jsonl"
    path.write_text('{"a": 1}\n{"a": 2, "sig": "deadbeef"}\n{oops\n')

    result = CliRunner().invoke(cli, ["audit-verify", str(path)])
    assert result.exit_code == 1
    assert "0 verified, 1 tampered, 1 unsigned, 1 unreadable" in result.output
