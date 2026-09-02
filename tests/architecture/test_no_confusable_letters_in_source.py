"""No Cyrillic or Greek letters in source. They are written as escapes.

The repository is public and English-only, and this package deliberately
handles letters chosen for impersonating Latin ones. A Cyrillic small er
renders as 'p'. A file holding that character literally is a file a reviewer
cannot read accurately, in exactly the way the attack intends.

So those codepoints are written as escape sequences, the way the bidi range
in injection_detector and input_sanitizer already was. A codepoint in a
table is inspectable; a glyph that looks like 'a' and is not one is the
payload.

Scope is these two alphabets, not all of ASCII's complement. The codebase
has used em-dashes, arrows, box drawing and check marks in prose and in
rendered output since it was written; those are typography, they are not
confusable with Latin letters, and a gate that failed on them would be a
demand to rewrite the repository rather than a rule anyone had.

Test data is exempt by location, not by judgement. tests/corpus holds
captured bytes and written payloads, and folding those into escapes would
change the thing being measured.
"""

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SOURCE_DIRS = ("cyberai", "tests")
_EXEMPT = ("tests/corpus",)


def _files() -> list[pathlib.Path]:
    out = []
    for directory in _SOURCE_DIRS:
        for path in sorted((_ROOT / directory).rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            if any(rel.startswith(prefix) for prefix in _EXEMPT):
                continue
            out.append(path)
    return out


# Cyrillic, Cyrillic Supplement, Greek and Coptic. The blocks whose letters
# are routinely substituted for Latin ones in injection payloads.
_BANNED_RANGES = ((0x0370, 0x03FF), (0x0400, 0x04FF), (0x0500, 0x052F))


def _is_banned(char: str) -> bool:
    point = ord(char)
    return any(low <= point <= high for low, high in _BANNED_RANGES)


def _offenders(path: pathlib.Path) -> list[tuple[int, str]]:
    hits = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        bad = sorted({c for c in line if _is_banned(c)})
        if bad:
            hits.append((number, " ".join(f"U+{ord(c):04X}" for c in bad)))
    return hits


def test_no_source_file_holds_a_confusable_letter() -> None:
    found = {
        path.relative_to(_ROOT).as_posix(): _offenders(path)
        for path in _files()
        if _offenders(path)
    }
    assert not found, (
        f"Cyrillic or Greek letters in source: {found}. Write the codepoint "
        "as an escape sequence instead, the way CONFUSABLE_TO_LATIN does."
    )


def test_the_scan_actually_covers_the_security_package() -> None:
    """A gate that checks nothing passes for the wrong reason."""
    scanned = {p.relative_to(_ROOT).as_posix() for p in _files()}
    assert "cyberai/core/security/injection_detector.py" in scanned
    assert len(scanned) > 100, len(scanned)


def test_the_corpus_is_exempt_and_still_holds_confusables() -> None:
    """The exemption is load-bearing: prove the samples it protects exist."""
    sample = _ROOT / "tests" / "corpus" / "injections" / "homoglyph-cyrillic.txt"
    body = sample.read_text(encoding="utf-8")
    assert any(_is_banned(c) for c in body), "the homoglyph sample lost its homoglyphs"


def test_the_rule_does_not_reach_beyond_confusable_letters() -> None:
    """Typography stays legal. The gate is about impersonation, not about ASCII."""
    for char in ("\u2014", "\u2192", "\u2713", "\u2500", "\u26a0"):
        assert not _is_banned(char), char
    for char in ("\u0430", "\u0433", "\u03b1", "\u0410"):
        assert _is_banned(char), char
