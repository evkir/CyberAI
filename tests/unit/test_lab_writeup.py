"""Tests for cyberai.lab.writeup."""

from __future__ import annotations

from cyberai.lab.flag_detector import FlagHit
from cyberai.lab.runner import ArtifactKind, LabArtifact, LabResult
from cyberai.lab.writeup import generate_writeup


def _solved_result() -> LabResult:
    return LabResult(
        name="brainpan",
        root="/oscp/machines/brainpan",
        artifacts=[
            LabArtifact("/m/loot/proof.txt", ArtifactKind.LOOT, 33),
            LabArtifact("/m/exploit/1-fuzz.py", ArtifactKind.EXPLOIT, 12),
            LabArtifact("/m/nmap/all-ports.txt", ArtifactKind.NMAP, 40),
        ],
        flags=[FlagHit("/m/loot/proof.txt", "oscp_hex32", "a" * 32)],
    )


def test_header_and_solved_status() -> None:
    md = generate_writeup(_solved_result())
    assert md.startswith("# Lab Writeup: brainpan")
    assert "**Status:** SOLVED" in md
    assert "**Flags captured:** 1" in md
    assert "**Artifacts collected:** 3" in md


def test_flag_table_present_when_solved() -> None:
    md = generate_writeup(_solved_result())
    assert "## Captured Flags" in md
    assert "oscp_hex32" in md
    assert "proof.txt" in md


def test_no_flag_table_when_unsolved() -> None:
    result = LabResult(
        name="empty",
        root="/m",
        artifacts=[LabArtifact("/m/nmap/scan.txt", ArtifactKind.NMAP, 10)],
        flags=[],
    )
    md = generate_writeup(result)
    assert "**Status:** UNSOLVED" in md
    assert "## Captured Flags" not in md


def test_artifact_summary_and_inventory() -> None:
    md = generate_writeup(_solved_result())
    assert "## Artifact Summary" in md
    assert "## Artifact Inventory" in md
    # Loot ordered before nmap per _KIND_ORDER.
    assert md.index("### loot") < md.index("### nmap")


def test_empty_result_has_header_only() -> None:
    result = LabResult(name="void", root="/m", artifacts=[], flags=[])
    md = generate_writeup(result)
    assert "# Lab Writeup: void" in md
    assert "## Artifact Summary" not in md
    assert "## Artifact Inventory" not in md
    assert "## Captured Flags" not in md


def test_output_ends_with_single_newline() -> None:
    md = generate_writeup(_solved_result())
    assert md.endswith("\n")
    assert not md.endswith("\n\n")


def test_inventory_lists_sizes() -> None:
    md = generate_writeup(_solved_result())
    assert "(33 bytes)" in md
    assert "(12 bytes)" in md


def test_summary_counts_by_kind() -> None:
    result = LabResult(
        name="multi",
        root="/m",
        artifacts=[
            LabArtifact("/m/nmap/a.txt", ArtifactKind.NMAP, 1),
            LabArtifact("/m/nmap/b.txt", ArtifactKind.NMAP, 1),
            LabArtifact("/m/loot/c.txt", ArtifactKind.LOOT, 1),
        ],
        flags=[FlagHit("/m/loot/c.txt", "flag", "flag{x}")],
    )
    md = generate_writeup(result)
    assert "| nmap | 2 |" in md
    assert "| loot | 1 |" in md
