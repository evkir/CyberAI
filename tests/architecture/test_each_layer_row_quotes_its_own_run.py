"""A row naming a configuration must carry that configuration's figures.

The existing rule checks every percentage in the research document against
the union of every committed report. That answers "did some run produce this
number", which its own docstring admits is weaker than "did the run this
sentence describes", and on 2026-10-09 the gap was paid for: the two-layer
row claimed 100.0% precision and 0.0% false positives for as long as the
benign class was captured tool output. Both figures were real. They belonged
to the row above.

A union cannot see that, because the layers share a corpus and the stronger
layer's precision is the weaker one's until something makes them differ.
Sixty server descriptions made them differ, and nothing failed.

So each row is read as a row. The layer in the first cell selects the report
the rest of the cells must come from, and a figure that travelled one row up
or down is now the failure it always was. The pairing is declared below
rather than parsed out of the prose: a table that renames its rows should
break this test and be looked at, not silently match a different artifact.

The first revision of this file compared a row against every percentage
anywhere in its report, and a mutant restoring the false 100.0%/0.0% pair
survived it: a report carries per-subclass figures too, and almost any
plausible number appears somewhere among them. Membership in a file is not
provenance. Each cell is therefore matched to the metric of its column,
read from the report's overall table by name.

What is deliberately not checked here is whether the artifacts themselves
are current. test_baseline_artifact_is_current and its combined twin hold
that, and duplicating it would put the same run behind two failures with one
cause.
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_EVAL = _ROOT / "examples" / "detector-eval"
_RESEARCH = _ROOT / "docs" / "research" / "detector-v2.md"

# (heading the table sits under, row label) -> the report that row describes.
_ROW_SOURCE = {
    ("## L1 — pattern layer", "L1"): _EVAL / "baseline.md",
    ("## L1 — pattern layer", "L1+L2"): _EVAL / "combined.md",
    ("## A public benchmark", "L1"): _EVAL / "agentdojo-l1.md",
    ("## A public benchmark", "L1+L2"): _EVAL / "agentdojo.md",
}

_PERCENT = re.compile(r"\d+\.\d%")
# Column order of the layer table, left to right after the label, mapped to
# the row label of the report's own overall table. Both tables are produced
# by the same renderer, so a renamed metric breaks this loudly.
_COLUMNS = ("recall", "precision", "false positive rate")


def _sections(text: str) -> dict[str, str]:
    """Every level-two section body, keyed by its heading line."""
    out: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if current is not None:
                out[current] = "\n".join(buf)
            current, buf = line.strip(), []
        elif current is not None:
            buf.append(line)
    if current is not None:
        out[current] = "\n".join(buf)
    return out


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip("|").split("|")]


def _layer_rows(section: str) -> dict[str, list[str]]:
    """{row label: the figures in that row, in column order}."""
    rows: dict[str, list[str]] = {}
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if cells and cells[0] in ("L1", "L1+L2"):
            rows[cells[0]] = [c for c in cells[1:] if _PERCENT.fullmatch(c)]
    return rows


def _overall(report: pathlib.Path) -> dict[str, str]:
    """The report's own overall figures, by metric name."""
    out: dict[str, str] = {}
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if len(cells) == 2 and cells[0] in _COLUMNS and _PERCENT.fullmatch(cells[1]):
            out[cells[0]] = cells[1]
    return out


def test_every_declared_row_exists() -> None:
    """A stale pairing is an exemption with nothing behind it."""
    sections = _sections(_RESEARCH.read_text(encoding="utf-8"))
    for (heading, label), report in _ROW_SOURCE.items():
        assert heading in sections, f"{heading!r} is gone from {_RESEARCH.name}"
        assert label in _layer_rows(sections[heading]), f"no {label} row under {heading!r}"
        assert report.is_file(), f"{report} is declared as a source and does not exist"
        missing = [m for m in _COLUMNS if m not in _overall(report)]
        assert not missing, f"{report.name} states no {missing}; the renderer changed"


def test_each_cell_is_the_metric_its_own_report_measured() -> None:
    sections = _sections(_RESEARCH.read_text(encoding="utf-8"))
    for (heading, label), report in _ROW_SOURCE.items():
        quoted = _layer_rows(sections[heading])[label]
        assert len(quoted) == len(_COLUMNS), (
            f"the {label} row under {heading!r} holds {len(quoted)} figures, "
            f"expected {len(_COLUMNS)}: {quoted}"
        )
        measured = _overall(report)
        for metric, cell in zip(_COLUMNS, quoted):
            assert cell == measured[metric], (
                f"{heading} / {label}: the {metric} cell says {cell}, "
                f"{report.name} measured {measured[metric]}."
            )
