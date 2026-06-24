"""Tests for the CTF challenge loader (CTFAdapter)."""

from __future__ import annotations

import json

from cyberai.bench.ctf import CTFTask
from cyberai.bench.ctf_loader import CTFAdapter


def test_ships_at_least_two_challenges():
    tasks = CTFAdapter().load_ctf_tasks()
    ids = {t.id for t in tasks}
    assert {"ctf-decode-the-base", "ctf-path-of-secrets"} <= ids
    assert all(isinstance(t, CTFTask) for t in tasks)


def test_load_tasks_projects_without_flag():
    tasks = CTFAdapter().load_tasks()
    assert tasks
    for t in tasks:
        assert t.suite == "ctf"
        # flag must never appear in the runner-facing task
        assert "flag{" not in t.success_criteria


def test_shipped_flags_are_solvable_from_files():
    # decode-the-base: note.txt base64-decodes to the flag
    import base64
    from pathlib import Path

    adapter = CTFAdapter()
    t = adapter.get_ctf_task("ctf-decode-the-base")
    assert t is not None
    note = Path(t.challenge_dir, "note.txt").read_text().strip()
    decoded = base64.b64decode(note).decode()
    assert t.check(decoded) is True


def test_missing_root_is_empty_suite(tmp_path):
    adapter = CTFAdapter(root=tmp_path / "nope")
    assert adapter.load_ctf_tasks() == []
    assert adapter.load_tasks() == []


def test_malformed_manifest_skipped(tmp_path):
    good = tmp_path / "good"
    good.mkdir()
    (good / "manifest.json").write_text(
        json.dumps(
            {"id": "g", "name": "g", "category": "web", "difficulty": "easy", "flag": "flag{g}"}
        )
    )
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "manifest.json").write_text("{ not json")
    incomplete = tmp_path / "incomplete"
    incomplete.mkdir()
    (incomplete / "manifest.json").write_text(json.dumps({"id": "x"}))

    tasks = CTFAdapter(root=tmp_path).load_ctf_tasks()
    assert [t.id for t in tasks] == ["g"]
