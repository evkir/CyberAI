"""Tests for the CTF flag-submission contract."""

from __future__ import annotations

from cyberai.bench.ctf import (
    CTFTask,
    extract_flag,
    flag_matches,
    normalize_flag,
)
from cyberai.bench.runner import BenchTask


def test_normalize_strips_outer_whitespace_only():
    assert normalize_flag("  flag{abc}\n") == "flag{abc}"
    assert normalize_flag("flag{a b}") == "flag{a b}"


def test_flag_matches_exact():
    assert flag_matches("flag{win}", "flag{win}") is True
    assert flag_matches(" flag{win}\n", "flag{win}") is True


def test_flag_mismatch_and_empty():
    assert flag_matches("flag{nope}", "flag{win}") is False
    assert flag_matches("", "flag{win}") is False
    assert flag_matches("flag{win}", "") is False


def test_flag_is_case_sensitive():
    assert flag_matches("FLAG{win}", "flag{win}") is False


def test_extract_flag_from_blob():
    assert extract_flag("noise flag{found_it} more") == "flag{found_it}"
    assert extract_flag("no flag here") is None
    assert extract_flag("flag{unterminated") is None


def test_extract_custom_format():
    assert extract_flag("CTF{xyz}", flag_format="CTF{") == "CTF{xyz}"


def test_ctf_task_check():
    t = CTFTask(id="c1", name="warmup", category="web", difficulty="easy", flag="flag{hello}")
    assert t.check("flag{hello}") is True
    assert t.check("flag{wrong}") is False


def test_ctf_task_projection_hides_flag():
    t = CTFTask(id="c1", name="warmup", category="crypto", difficulty="easy", flag="flag{secret}")
    task = t.to_bench_task()
    assert isinstance(task, BenchTask)
    assert task.suite == "ctf"
    assert "flag{secret}" not in task.success_criteria
    assert task.metadata["category"] == "crypto"
