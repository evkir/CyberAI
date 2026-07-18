"""Tests for cyberai.lab.runner."""

from __future__ import annotations

from pathlib import Path

from cyberai.lab.runner import (
    ArtifactKind,
    LabArtifact,
    LabMachine,
    classify_artifact,
    run_machine,
)


def _write(root: Path, rel: str, content: str = "x") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _brainpan(root: Path) -> Path:
    """Recreate the uniform nmap/exploit/loot layout of a solved box."""
    m = root / "brainpan"
    _write(m, "nmap/all-ports.txt", "22/tcp open")
    _write(m, "nmap/ffuf-10000.json", "{}")
    _write(m, "exploit/1-fuzz.py", "print('fuzz')")
    _write(m, "loot/proof.txt", "0123456789abcdef0123456789abcdef")
    return m


def test_classify_by_dir_hint(tmp_path: Path) -> None:
    assert classify_artifact(tmp_path / "nmap" / "scan.txt") == ArtifactKind.NMAP
    assert classify_artifact(tmp_path / "exploit" / "x.py") == ArtifactKind.EXPLOIT
    assert classify_artifact(tmp_path / "loot" / "hash.txt") == ArtifactKind.LOOT


def test_classify_by_suffix_when_no_dir_hint(tmp_path: Path) -> None:
    assert classify_artifact(tmp_path / "detailed.gnmap") == ArtifactKind.NMAP
    assert classify_artifact(tmp_path / "fullscan.xml") == ArtifactKind.NMAP
    assert classify_artifact(tmp_path / "fsociety.dic") == ArtifactKind.WORDLIST
    assert classify_artifact(tmp_path / "root.py") == ArtifactKind.EXPLOIT


def test_classify_other_fallback(tmp_path: Path) -> None:
    assert classify_artifact(tmp_path / "notes.md") == ArtifactKind.OTHER


def test_dir_hint_wins_over_suffix(tmp_path: Path) -> None:
    # A .py inside loot/ is loot, not exploit — directory hint takes priority.
    assert classify_artifact(tmp_path / "loot" / "creds.py") == ArtifactKind.LOOT


def test_missing_root_empty(tmp_path: Path) -> None:
    m = LabMachine(tmp_path / "ghost")
    assert m.collect_artifacts() == []
    result = m.run()
    assert result.artifacts == []
    assert result.flags == []
    assert result.solved is False


def test_collect_uniform_layout(tmp_path: Path) -> None:
    m = LabMachine(_brainpan(tmp_path))
    arts = m.collect_artifacts()
    kinds = {a.kind for a in arts}
    assert ArtifactKind.NMAP in kinds
    assert ArtifactKind.EXPLOIT in kinds
    assert ArtifactKind.LOOT in kinds


def test_collect_flat_layout(tmp_path: Path) -> None:
    # mrrobot-style: everything dumped at the machine root, no subdirs.
    m = tmp_path / "mrrobot"
    _write(m, "detailed.gnmap", "host up")
    _write(m, "hash.txt", "deadbeef")
    _write(m, "fsociety.dic", "a\nb\n")
    arts = LabMachine(m).collect_artifacts()
    by_kind = {a.kind for a in arts}
    assert ArtifactKind.NMAP in by_kind
    assert ArtifactKind.WORDLIST in by_kind


def test_run_detects_flag_and_marks_solved(tmp_path: Path) -> None:
    result = run_machine(_brainpan(tmp_path))
    assert result.name == "brainpan"
    assert result.solved is True
    assert any(f.pattern_name == "oscp_hex32" for f in result.flags)


def test_run_unsolved_when_no_flag(tmp_path: Path) -> None:
    m = tmp_path / "empty"
    _write(m, "nmap/scan.txt", "nothing here")
    result = run_machine(m)
    assert result.solved is False


def test_extra_flag_pattern_flows_through(tmp_path: Path) -> None:
    m = tmp_path / "custom"
    _write(m, "loot/notes.txt", "SECRET-2026-XYZ")
    result = run_machine(m, extra_flag_patterns=[r"SECRET-\d{4}-[A-Z]+"])
    assert result.solved is True
    assert any(f.pattern_name == "custom_0" for f in result.flags)


def test_artifacts_by_kind_filter(tmp_path: Path) -> None:
    result = run_machine(_brainpan(tmp_path))
    nmaps = result.artifacts_by_kind(ArtifactKind.NMAP)
    assert nmaps
    assert all(a.kind == ArtifactKind.NMAP for a in nmaps)


def test_labartifact_frozen() -> None:
    a = LabArtifact(path="p", kind=ArtifactKind.OTHER, size=1)
    try:
        a.size = 2  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised


def test_stat_oserror_skips_file(tmp_path: Path, monkeypatch) -> None:
    # A file vanishing between listing and stat() is skipped, not fatal.
    m = tmp_path / "racy"
    _write(m, "loot/proof.txt", "deadbeefdeadbeefdeadbeefdeadbeef")

    real_stat = Path.stat

    def boom(self, *a, **k):
        if self.name == "proof.txt":
            raise OSError("gone")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", boom)
    arts = LabMachine(m).collect_artifacts()
    assert all(Path(a.path).name != "proof.txt" for a in arts)
