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
import re
from pathlib import Path

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

# Both files are located from this file rather than from the imported
# package. Deriving a repository path from cyberai.__file__ points at
# wherever the package happens to be installed, and when a released wheel
# sat in site-packages this test went looking for a README beside it and
# failed with FileNotFoundError -- a symptom of the environment, reported
# as if the README were at fault.
_ROOT = Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_MAIN = _ROOT / "cyberai" / "__main__.py"


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


# Both spellings of the invocation the README shows.
_INVOCATION = re.compile(r"^(?:python -m )?cyberai status\b")


def _status_invocations() -> list[str]:
    return [
        line for line in _README.read_text(encoding="utf-8").splitlines() if _INVOCATION.match(line)
    ]


# Two labels, not one. A single field name appears in prose that is not a
# description at all -- the dry-run line mentions an API key while describing
# something else entirely -- and treating that as a field list would make the
# rule fire on comments nobody meant as documentation.
_MIN_LABELS = 2


def _annotations() -> list[str]:
    """Comment text attached to a status invocation, inline or on the line above.

    The fix for DK looked at inline comments only. A comment sitting above
    the command reads as its description to every human eye and to no test,
    so a field list written there would drift unwatched. Section labels are
    not excluded by position -- they are excluded below, by not naming
    fields.
    """
    lines = _README.read_text(encoding="utf-8").splitlines()
    found = []
    for index, line in enumerate(lines):
        if not _INVOCATION.match(line):
            continue
        if "#" in line:
            found.append(line.split("#", 1)[1])
        above = lines[index - 1].strip() if index else ""
        if above.startswith("#") and not above.startswith("##"):
            found.append(above.split("#", 1)[1])
    return found


def _describes_output(text: str) -> bool:
    """Whether a comment is listing what the panel prints."""
    lowered = text.lower()
    named = sum(1 for label in _printed_labels() if label.lower() in lowered)
    return named >= _MIN_LABELS


def _described_invocations() -> list[str]:
    """The comments that say what the command prints."""
    return [text for text in _annotations() if _describes_output(text)]


def _readme_status_line() -> str:
    """The one invocation that says what the command prints.

    Reading the first line that matched made a second description invisible.
    The README shows the command twice -- once with the field list, once as
    `python -m cyberai status` in the quick-start block -- so a description
    added above the checked one would have been read in its place while the
    older one drifted unread and still wrong.

    A comment on the line above an invocation is out of scope: the quick-start
    block carries one, and it labels a section rather than describing output.
    """
    described = _described_invocations()
    assert len(described) == 1, (
        f"{len(described)} invocations describe the output; this reads one of them "
        f"and the others drift unchecked: {described}"
    )
    return described[0]


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
