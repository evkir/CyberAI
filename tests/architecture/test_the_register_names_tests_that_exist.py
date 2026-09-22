"""Every test the risk register names must exist in this tree.

The register replaced a page that had gone stale silently. A page of
statuses rots the same way, and faster: a risk marked closed because a test
holds it stays marked closed after the test is renamed, deleted, or folded
into another file. The reader then believes a guard exists that does not.

So a status is only as good as the node id beside it, and the node id is
checked here. Function names are compared rather than whole node ids: one
of the tests named is parametrised, so its real ids carry a suffix this
document has no business tracking.

The pattern that finds references is checked against the table rather than
trusted. An earlier draft of this file used a character class without
digits, which silently skipped all three web3 references -- a narrow
resolver returns a short list, not a clean one. Counting the rows that
carry a reference and the references the pattern found, and requiring them
to agree, is what makes the first assertion mean anything.
"""

import ast
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_REGISTER = _ROOT / "docs" / "architecture" / "risk-register.md"

_REFERENCE = re.compile(r"tests/[A-Za-z0-9_/]+\.py::[A-Za-z0-9_]+")
_ROW = re.compile(r"^\|\s*(\d+)\s*\|(.+?)\|\s*(\w+)\s*\|\s*([\w/-]+)\s*\|(.+?)\|\s*$")
_DECLARED = {"closed", "partly", "open", "unguarded"}


def rows(text: str) -> list[tuple[int, str, str]]:
    """(number, status, evidence cell) for each numbered row in the register.

    The table grew a fourth column on 2026-09-22 saying what kind of
    assertion holds each closed row. Both readers of this page matched it
    into the evidence cell and kept working, which is the wrong reason for
    a check to be green: the pattern has to know the shape it reads.
    """
    out = []
    for line in text.splitlines():
        match = _ROW.match(line)
        if match:
            out.append((int(match.group(1)), match.group(3), match.group(5)))
    return out


def stale_references(text: str, root: pathlib.Path) -> list[str]:
    """References whose file or whose function is not in the tree."""
    missing = []
    for ref in _REFERENCE.findall(text):
        rel, _, func = ref.partition("::")
        path = root / rel
        if not path.exists():
            missing.append(ref)
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if func not in names:
            missing.append(ref)
    return missing


def test_every_reference_names_a_function_that_exists() -> None:
    text = _REGISTER.read_text(encoding="utf-8")
    stale = stale_references(text, _ROOT)
    assert not stale, (
        f"the register names tests that are not in this tree: {stale}. "
        "A status resting on a renamed test is the failure this page replaced."
    )


def test_the_pattern_sees_every_reference_the_table_carries() -> None:
    """Otherwise the assertion above checks whatever the pattern happened to match."""
    text = _REGISTER.read_text(encoding="utf-8")
    carried = sum(cell.count("::") for _, _, cell in rows(text))
    found = len(_REFERENCE.findall(text))
    assert carried > 0, "no row carries a reference -- the row pattern broke"
    assert found == carried, (
        f"the table carries {carried} references and the pattern found {found}. "
        "One of the two is narrower than the register."
    )


def test_every_closed_row_carries_a_reference() -> None:
    text = _REGISTER.read_text(encoding="utf-8")
    naked = [num for num, status, cell in rows(text) if status == "closed" and "::" not in cell]
    assert not naked, f"rows claiming closed with nothing behind them: {naked}"


def test_every_status_is_one_of_the_declared_ones() -> None:
    """A vocabulary the page states and the page then departs from is prose."""
    text = _REGISTER.read_text(encoding="utf-8")
    unknown = sorted({status for _, status, _ in rows(text) if status not in _DECLARED})
    assert not unknown, f"statuses the page never defines: {unknown}"


def test_a_planted_stale_reference_is_caught(tmp_path: pathlib.Path) -> None:
    """The check has to be able to say no, or it says nothing."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_planted.py").write_text("def test_real(): pass\n", encoding="utf-8")
    live = "tests/test_planted.py::test_real"
    dead = "tests/test_planted.py::test_gone"
    assert stale_references(f"| 1 | r | closed | `{live}` |", tmp_path) == []
    assert stale_references(f"| 1 | r | closed | `{dead}` |", tmp_path) == [dead]
