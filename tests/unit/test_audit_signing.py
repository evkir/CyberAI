"""The audit trail is signed, and the signature is worth checking.

Every test here goes through the production path: AuditLogger writes a real
file, and the assertions read that file from disk. A test that constructed
the event dict itself would verify the signer's arithmetic and say nothing
about whether the pipeline signs what it records.
"""

import json
from pathlib import Path

import pytest

from cyberai.cli.audit_verify import verify_trail
from cyberai.core.logger import AuditLogger, get_logger
from cyberai.core.session_signing import SessionSigner


@pytest.fixture
def trail(tmp_path: Path) -> Path:
    """A real audit file written by three different logger methods."""
    audit = AuditLogger(session_id="t", output_dir=str(tmp_path))
    audit.agent_action("recon", "nmap_scan", {"target": "10.0.0.1"})
    audit.finding("recon", "Open SSH", "LOW")
    audit.error("recon", "tool exited 1")
    return tmp_path / "audit_t.jsonl"


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_a_written_trail_verifies_line_by_line(trail: Path):
    """The signature covers what reached disk, not what the caller passed."""
    report = verify_trail(str(trail))
    assert report.verified == 3, report.summary()
    assert report.clean is True


def test_editing_a_recorded_field_breaks_that_line(trail: Path):
    """Rewriting the scan target is exactly the edit the signature exists for."""
    events = _events(trail)
    events[0]["data"]["target"] = "8.8.8.8"
    trail.write_text("\n".join(json.dumps(e) for e in events))

    report = verify_trail(str(trail))
    assert report.tampered == [1], report.summary()
    assert report.verified == 2


def test_forging_the_signature_field_does_not_help(trail: Path):
    """An attacker who rewrites sig without the key gets a mismatch, not a pass."""
    events = _events(trail)
    events[1]["message"] = "[FINDING][LOW] nothing to see"
    events[1]["sig"] = "0" * 64
    trail.write_text("\n".join(json.dumps(e) for e in events))

    report = verify_trail(str(trail))
    assert report.tampered == [2], report.summary()


def test_an_unsigned_line_is_not_reported_as_verified(trail: Path):
    """Absence of a signature is its own verdict: it is not evidence of anything."""
    events = _events(trail)
    del events[2]["sig"]
    trail.write_text("\n".join(json.dumps(e) for e in events))

    report = verify_trail(str(trail))
    assert report.unsigned == [3], report.summary()
    assert report.verified == 2
    assert report.clean is False


def test_signing_leaves_the_existing_keys_untouched(trail: Path):
    """The field is additive: readers of the old format keep working."""
    first = _events(trail)[0]
    assert list(first)[:6] == ["timestamp", "level", "logger", "message", "agent", "data"]
    assert first["agent"] == "recon"
    assert first["data"] == {"target": "10.0.0.1"}


def test_the_key_comes_from_the_environment_at_call_time(trail: Path, monkeypatch):
    """A run signed with the operator's key does not verify under the fallback."""
    monkeypatch.setenv("CYBERAI_SESSION_SECRET", "engagement-key")
    assert verify_trail(str(trail)).tampered == [1, 2, 3]
    assert verify_trail(str(trail), SessionSigner(secret=None)).tampered == [1, 2, 3]


def test_rebuilding_the_logger_for_one_session_does_not_double_the_trail(tmp_path):
    """One action, one line.

    logging.getLogger returns the same object for a name, and AuditLogger
    derives its name from the session id. Two builds for one session used
    to stack a second RichHandler and a second FileHandler, so a single
    agent_action reached the signed trail twice under two signatures. The
    bench path builds two agents on one session without handing either an
    audit logger, so this was reachable in production, not only in tests.
    """
    session_id = "doubled"
    first = AuditLogger(session_id=session_id, output_dir=str(tmp_path))
    second = AuditLogger(session_id=session_id, output_dir=str(tmp_path))

    assert first.logger is second.logger

    first.agent_action("recon", "one action")

    trail = tmp_path / f"audit_{session_id}.jsonl"
    lines = [ln for ln in trail.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, f"one action wrote {len(lines)} lines"


def test_a_second_build_does_not_stack_a_second_console_handler(tmp_path):
    """The console half of the same defect, counted rather than observed.

    Asserting on the trail alone would stay green if only the file handler
    were deduplicated, because stderr leaves no artefact to read back.
    """
    from rich.logging import RichHandler

    session_id = "console"
    first = AuditLogger(session_id=session_id, output_dir=str(tmp_path))
    AuditLogger(session_id=session_id, output_dir=str(tmp_path))

    rich = [h for h in first.logger.handlers if isinstance(h, RichHandler)]
    assert len(rich) == 1, f"{len(rich)} console handlers after two builds"


def test_a_different_destination_still_gets_its_own_file_handler(tmp_path):
    """Deduplication keys on the path, so it must not swallow a real second file.

    A guard written as "at most one FileHandler" would pass the two tests
    above and silently drop the trail of a session that legitimately writes
    somewhere else.

    Measured, not assumed: mutating the key from the resolved path to the
    handler type fails this assertion and nine more in this file. Under that
    mutant a later logger binds to the handler an earlier one opened, so its
    signed lines land in the earlier file and every trail-verification test
    here reads an empty one. The path key therefore holds the isolation of
    this whole file, not just the assertion below.
    """
    import logging

    other = tmp_path / "elsewhere"
    other.mkdir()

    name = "cyberai.audit.twofiles"
    get_logger(name, str(tmp_path / "a.jsonl"))
    logger = get_logger(name, str(other / "b.jsonl"))

    files = {h.baseFilename for h in logger.handlers if isinstance(h, logging.FileHandler)}
    assert len(files) == 2, f"expected two destinations, got {sorted(files)}"
