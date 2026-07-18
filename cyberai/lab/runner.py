"""Offline runner for local practice-lab machines.

A "machine" is a directory of artifacts produced during a solved practice
box (recon scans, exploit scripts, looted files). Structure is not uniform
across boxes — some use nmap/exploit/loot subdirs, others keep everything
flat — so artifacts are categorised by parent-directory hint first, then by
filename/extension. The runner parses these artifacts offline and detects
captured flags; it never touches the network. An optional live scan is
exposed behind a config flag but is not driven by the offline path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from cyberai.lab.flag_detector import FlagHit, detect_flags

logger = logging.getLogger("cyberai.lab.runner")


class ArtifactKind(str, Enum):
    """Coarse category an artifact file falls into."""

    NMAP = "nmap"
    EXPLOIT = "exploit"
    LOOT = "loot"
    WORDLIST = "wordlist"
    OTHER = "other"


# Parent directory names that pin an artifact to a category outright.
_DIR_HINTS: dict[str, ArtifactKind] = {
    "nmap": ArtifactKind.NMAP,
    "exploit": ArtifactKind.EXPLOIT,
    "loot": ArtifactKind.LOOT,
}

# Filename suffixes used when no directory hint applies.
_SUFFIX_HINTS: dict[str, ArtifactKind] = {
    ".nmap": ArtifactKind.NMAP,
    ".gnmap": ArtifactKind.NMAP,
    ".xml": ArtifactKind.NMAP,
    ".dic": ArtifactKind.WORDLIST,
    ".py": ArtifactKind.EXPLOIT,
}


@dataclass(frozen=True)
class LabArtifact:
    """One collected file: its path, category, and size in bytes."""

    path: str
    kind: ArtifactKind
    size: int


@dataclass
class LabResult:
    """Outcome of parsing one machine directory offline."""

    name: str
    root: str
    artifacts: list[LabArtifact] = field(default_factory=list)
    flags: list[FlagHit] = field(default_factory=list)

    @property
    def solved(self) -> bool:
        """A machine counts as solved once at least one flag is captured."""
        return bool(self.flags)

    def artifacts_by_kind(self, kind: ArtifactKind) -> list[LabArtifact]:
        return [a for a in self.artifacts if a.kind == kind]


def classify_artifact(path: Path) -> ArtifactKind:
    """Categorise a file by parent-directory hint, then filename suffix."""
    for part in path.parts:
        hint = _DIR_HINTS.get(part.lower())
        if hint is not None:
            return hint
    return _SUFFIX_HINTS.get(path.suffix.lower(), ArtifactKind.OTHER)


class LabMachine:
    """A single practice-lab machine rooted at a directory of artifacts."""

    def __init__(self, root: str | Path, extra_flag_patterns: list[str] | None = None):
        self.root = Path(root)
        self.extra_flag_patterns = extra_flag_patterns or []

    def collect_artifacts(self) -> list[LabArtifact]:
        """Walk the machine directory and categorise every readable file.
        A missing root yields an empty list rather than raising."""
        if not self.root.is_dir():
            return []
        out: list[LabArtifact] = []
        for path in sorted(self.root.rglob("*")):
            try:
                if not path.is_file():
                    continue
                size = path.stat().st_size
            except OSError:
                # File vanished or became unreadable mid-walk: skip it.
                continue
            out.append(LabArtifact(path=str(path), kind=classify_artifact(path), size=size))
        return out

    def run(self) -> LabResult:
        """Parse the machine offline: collect artifacts and detect flags."""
        return LabResult(
            name=self.root.name,
            root=str(self.root),
            artifacts=self.collect_artifacts(),
            flags=detect_flags(self.root, self.extra_flag_patterns),
        )


def run_machine(root: str | Path, extra_flag_patterns: list[str] | None = None) -> LabResult:
    """Convenience wrapper: build a LabMachine and run it offline."""
    return LabMachine(root, extra_flag_patterns).run()
