"""Markdown writeup generation from a parsed lab machine.

Turns a LabResult into a human-readable Markdown report: solved status,
captured flags, and an inventory of collected artifacts grouped by kind.
Output is deterministic (stable ordering) and self-contained.
"""

from __future__ import annotations

from collections import Counter

from cyberai.lab.runner import ArtifactKind, LabResult

# Order kinds appear in the writeup, most interesting first.
_KIND_ORDER: tuple[ArtifactKind, ...] = (
    ArtifactKind.LOOT,
    ArtifactKind.EXPLOIT,
    ArtifactKind.NMAP,
    ArtifactKind.WORDLIST,
    ArtifactKind.OTHER,
)


def _flag_table(result: LabResult) -> list[str]:
    lines = ["## Captured Flags", "", "| Pattern | Value | File |", "| --- | --- | --- |"]
    for hit in result.flags:
        filename = hit.path.rsplit("/", 1)[-1]
        lines.append(f"| `{hit.pattern_name}` | `{hit.value}` | {filename} |")
    lines.append("")
    return lines


def _artifact_summary(result: LabResult) -> list[str]:
    counts: Counter[ArtifactKind] = Counter(a.kind for a in result.artifacts)
    lines = ["## Artifact Summary", "", "| Kind | Count |", "| --- | --- |"]
    for kind in _KIND_ORDER:
        if counts.get(kind):
            lines.append(f"| {kind.value} | {counts[kind]} |")
    lines.append("")
    return lines


def _artifact_inventory(result: LabResult) -> list[str]:
    lines = ["## Artifact Inventory", ""]
    for kind in _KIND_ORDER:
        items = result.artifacts_by_kind(kind)
        if not items:
            continue
        lines.append(f"### {kind.value}")
        for art in items:
            lines.append(f"- `{art.path}` ({art.size} bytes)")
        lines.append("")
    return lines


def generate_writeup(result: LabResult) -> str:
    """Render a Markdown writeup for one parsed lab machine."""
    status = "SOLVED" if result.solved else "UNSOLVED"
    lines: list[str] = [
        f"# Lab Writeup: {result.name}",
        "",
        f"**Machine:** `{result.name}`  ",
        f"**Root:** `{result.root}`  ",
        f"**Status:** {status}  ",
        f"**Flags captured:** {len(result.flags)}  ",
        f"**Artifacts collected:** {len(result.artifacts)}",
        "",
    ]
    if result.flags:
        lines += _flag_table(result)
    if result.artifacts:
        lines += _artifact_summary(result)
        lines += _artifact_inventory(result)
    return "\n".join(lines).rstrip() + "\n"
