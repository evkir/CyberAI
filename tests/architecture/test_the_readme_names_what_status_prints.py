"""The one-line README description of status covers every line status prints.

The description named three of the ten fields the panel already had and said
nothing about the two this branch added. A summary that lists a subset reads
as the whole: an operator who wants to know whether their toolchain resolves
has no reason to run a command advertised as printing provider and sampling.

Grouping is the point of the line, so the test states the grouping rather than
demanding every label appear verbatim. The groups are checked against the
labels taken out of the status source, so a field added to the panel and
omitted here fails, and a group that outlives its fields fails too.
"""

from __future__ import annotations

import ast
from pathlib import Path

import cyberai

# what the README line calls it -> the labels the panel prints under it
_STATUS_GROUPS = {
    "provider": ["Provider", "Model"],
    "output": ["Output"],
    "trust boundary": ["Injection policy", "Injection threshold", "L2 classifier"],
    "sampling": ["Temperature", "Seed"],
    "air-gap": ["Air-gapped"],
    "credentials": ["API key"],
    "toolchain": ["Tools found", "Tools missing"],
}

_README = Path(cyberai.__file__).parent.parent / "README.md"
_MAIN = Path(cyberai.__file__).parent / "__main__.py"


def _printed_labels() -> set[str]:
    """Every label the status panel writes, read out of its f-strings."""
    for node in ast.walk(ast.parse(_MAIN.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef) and node.name == "status":
            labels = set()
            for inner in ast.walk(node):
                if isinstance(inner, ast.JoinedStr):
                    for value in inner.values:
                        if isinstance(value, ast.Constant):
                            for line in str(value.value).split("\n"):
                                if ":" in line:
                                    labels.add(line.split(":")[0].strip())
            return labels
    raise AssertionError("no status command in __main__")


def _readme_status_line() -> str:
    for line in _README.read_text(encoding="utf-8").splitlines():
        if line.startswith("cyberai status"):
            return line
    raise AssertionError("README does not show the status command")


def test_the_groups_cover_exactly_the_labels_the_panel_prints():
    grouped = {label for labels in _STATUS_GROUPS.values() for label in labels}
    printed = _printed_labels()
    assert grouped == printed, (
        f"grouped but not printed: {grouped - printed}, printed but ungrouped: {printed - grouped}"
    )


def test_the_readme_line_names_every_group():
    line = _readme_status_line()
    absent = [group for group in _STATUS_GROUPS if group not in line]
    assert not absent, f"the README line does not mention: {absent}"
