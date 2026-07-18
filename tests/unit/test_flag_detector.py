"""Tests for cyberai.lab.flag_detector."""

from __future__ import annotations

from pathlib import Path

from cyberai.lab.flag_detector import (
    FlagHit,
    detect_flags,
    flagged_files,
    has_flag_name,
)


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_missing_root_returns_empty(tmp_path: Path) -> None:
    assert detect_flags(tmp_path / "nope") == []


def test_detects_oscp_hex32(tmp_path: Path) -> None:
    _write(tmp_path, "loot/proof.txt", "0123456789abcdef0123456789abcdef\n")
    hits = detect_flags(tmp_path)
    assert any(h.pattern_name == "oscp_hex32" for h in hits)
    assert hits[0].value == "0123456789abcdef0123456789abcdef"


def test_hex32_word_boundary_rejects_longer_hash(tmp_path: Path) -> None:
    # A 40-char sha1 must not be reported as a 32-hex OSCP flag.
    _write(tmp_path, "notes.txt", "da39a3ee5e6b4b0d3255bfef95601890afd80709\n")
    hits = detect_flags(tmp_path)
    assert not any(h.pattern_name == "oscp_hex32" for h in hits)


def test_detects_htb_thm_flag_braces(tmp_path: Path) -> None:
    _write(tmp_path, "a.txt", "HTB{pwned_the_box}")
    _write(tmp_path, "b.txt", "THM{try_harder}")
    _write(tmp_path, "c.txt", "flag{generic_ctf}")
    names = {h.pattern_name for h in detect_flags(tmp_path)}
    assert {"htb", "thm", "flag"} <= names


def test_extra_pattern_matches(tmp_path: Path) -> None:
    _write(tmp_path, "x.txt", "CTF-2026-SECRET")
    hits = detect_flags(tmp_path, extra_patterns=[r"CTF-\d{4}-[A-Z]+"])
    assert any(h.pattern_name == "custom_0" and h.value == "CTF-2026-SECRET" for h in hits)


def test_invalid_extra_pattern_is_skipped(tmp_path: Path) -> None:
    _write(tmp_path, "y.txt", "flag{ok}")
    # Unbalanced bracket is an invalid regex; scan must still succeed.
    hits = detect_flags(tmp_path, extra_patterns=["[unterminated"])
    assert any(h.pattern_name == "flag" for h in hits)


def test_oversized_file_skipped(tmp_path: Path) -> None:
    big = "a" * (1_048_576 + 1)  # 1 MiB + 1, all non-flag chars
    _write(tmp_path, "wordlist.dic", big)
    _write(tmp_path, "loot/proof.txt", "ffffffffffffffffffffffffffffffff")
    hits = detect_flags(tmp_path)
    # The proof flag is still found; the oversized file simply contributes none.
    assert any(h.value == "f" * 32 for h in hits)


def test_binary_file_skipped(tmp_path: Path) -> None:
    p = tmp_path / "loot" / "shell.bin"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x00\xff\xfe HTB{not_utf8}")
    # Invalid UTF-8 → strict decode fails → file skipped, no crash.
    assert detect_flags(tmp_path) == []


def test_dedup_same_hit(tmp_path: Path) -> None:
    _write(tmp_path, "dup.txt", "flag{x}\nflag{x}\n")
    hits = [h for h in detect_flags(tmp_path) if h.pattern_name == "flag"]
    # Two identical lines collapse on (path, name, value) → one hit.
    assert len(hits) == 1


def test_flagged_files_distinct_order(tmp_path: Path) -> None:
    _write(tmp_path, "loot/proof.txt", "flag{a} flag{b}")
    _write(tmp_path, "loot/root.txt", "HTB{c}")
    hits = detect_flags(tmp_path)
    files = flagged_files(hits)
    assert len(files) == len(set(files))
    assert all(f.endswith(".txt") for f in files)


def test_has_flag_name() -> None:
    assert has_flag_name("/x/proof.txt")
    assert has_flag_name("LOCAL.TXT")
    assert not has_flag_name("nmap.txt")


def test_flaghit_is_frozen() -> None:
    h = FlagHit(path="p", pattern_name="flag", value="flag{z}")
    try:
        h.value = "other"  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised
