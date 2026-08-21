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
from cyberai.core.logger import AuditLogger
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
