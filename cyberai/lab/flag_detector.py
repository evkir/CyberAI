"""Flag detection for local practice-lab artifacts.

Scans a machine directory for captured flags using two signals: filename
hints (proof.txt, local.txt, ...) and content patterns matched anywhere in
readable text files. Ships built-in patterns for common lab formats and
accepts extra caller-supplied regexes. Fully offline and dependency-free;
a missing directory or unreadable file never raises — it is simply skipped.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("cyberai.lab.flag_detector")

# Filenames that conventionally hold a flag on practice machines.
_FLAG_FILENAMES = frozenset({"proof.txt", "local.txt", "root.txt", "user.txt", "flag.txt"})

# Built-in content patterns. Order matters only for reporting; all are tried.
# OSCP proof/local flags are 32 lowercase hex chars on their own; the word
# boundaries avoid matching the tail of a longer hash.
_BUILTIN_PATTERNS: tuple[tuple[str, str], ...] = (
    ("htb", r"HTB\{[^}]{1,256}\}"),
    ("thm", r"THM\{[^}]{1,256}\}"),
    ("flag", r"flag\{[^}]{1,256}\}"),
    ("oscp_hex32", r"\b[0-9a-f]{32}\b"),
)

# Files above this size are skipped for the content scan (wordlists, binaries).
_MAX_CONTENT_BYTES = 1_048_576  # 1 MiB


@dataclass(frozen=True)
class FlagHit:
    """One detected flag: where it was found, which pattern matched, its value."""

    path: str
    pattern_name: str
    value: str


def _compile_patterns(extra: list[str] | None) -> list[tuple[str, re.Pattern[str]]]:
    """Compile built-in plus extra patterns. A malformed extra regex is logged
    and skipped rather than aborting the whole scan."""
    compiled: list[tuple[str, re.Pattern[str]]] = [
        (name, re.compile(rx)) for name, rx in _BUILTIN_PATTERNS
    ]
    for i, rx in enumerate(extra or []):
        try:
            compiled.append((f"custom_{i}", re.compile(rx)))
        except re.error as exc:
            logger.warning("skipping invalid flag pattern %r: %s", rx, exc)
    return compiled


def _scan_file(path: Path, patterns: list[tuple[str, re.Pattern[str]]]) -> list[FlagHit]:
    """Scan one file's text content for every pattern. Unreadable or oversized
    files yield nothing."""
    try:
        if path.stat().st_size > _MAX_CONTENT_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return []
    hits: list[FlagHit] = []
    for name, rx in patterns:
        for m in rx.finditer(text):
            hits.append(FlagHit(path=str(path), pattern_name=name, value=m.group(0)))
    return hits


def detect_flags(root: str | Path, extra_patterns: list[str] | None = None) -> list[FlagHit]:
    """Recursively scan `root` for captured flags.

    Returns hits from both flag-named files and any readable text file whose
    content matches a built-in or caller-supplied pattern. A missing root
    yields an empty list. Results are de-duplicated on (path, pattern, value).
    """
    root_path = Path(root)
    if not root_path.is_dir():
        return []
    patterns = _compile_patterns(extra_patterns)
    seen: set[tuple[str, str, str]] = set()
    out: list[FlagHit] = []
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        for hit in _scan_file(path, patterns):
            key = (hit.path, hit.pattern_name, hit.value)
            if key not in seen:
                seen.add(key)
                out.append(hit)
    return out


def flagged_files(hits: list[FlagHit]) -> list[str]:
    """Distinct file paths that yielded at least one flag, order-preserving."""
    seen: set[str] = set()
    out: list[str] = []
    for h in hits:
        if h.path not in seen:
            seen.add(h.path)
            out.append(h.path)
    return out


def has_flag_name(path: str | Path) -> bool:
    """True if the filename is a conventional flag filename."""
    return Path(path).name.lower() in _FLAG_FILENAMES
