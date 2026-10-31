"""Counts on the scope page are written as digits, and the tree answers them.

A sentence counting something in the tree is a measurement whichever way it
is written, but only digits are readable by a guard. Five such sentences on
docs/architecture/typing-scope.md spelled their counts in words, so nothing
compared them with the manifest, the source or the page itself. They were
rewritten in the same commit as this file, because a guard reading a form
the page does not use is worse than no guard: it is green on absence.

The counts held here answer to different parts of the tree -- the manifest,
a dict literal, the imports of a package, the page's own table -- so each
reads its own standard rather than a shared snapshot. None of them is dated
on the page, which is why they are gated at all: a dated count is a record
and `test_the_prose_quotes_the_measured_edge.py` explains why pinning one
would red on every release.

This file states its own claim about spelled numerals through `__doc__`
rather than through the patterns below, which hold the digits they match.
A guard that read itself as one of the texts it checks would find its own
examples and fail on them.
"""

import ast
import pathlib
import re
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PAGE = _ROOT / "docs" / "architecture" / "typing-scope.md"
_MANIFEST = _ROOT / "pyproject.toml"
_BENCH = _ROOT / "cyberai" / "cli" / "bench.py"
_PACKAGE = _ROOT / "cyberai"


def _page() -> str:
    return _PAGE.read_text(encoding="utf-8")


def _stated(pattern: str, where: str) -> int:
    """The single number the page states in this shape."""
    found = re.findall(pattern, _page())
    assert len(found) == 1, f"the page states {where} {len(found)} times, not once"
    return int(found[0])


def _declared_directories() -> list[str]:
    files = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))["tool"]["mypy"]["files"]
    return [entry for entry in files if not entry.endswith(".py")]


def _live_engine_keys() -> list[str]:
    tree = ast.parse(_BENCH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        target = getattr(node, "target", None)
        if isinstance(node, ast.AnnAssign) and isinstance(target, ast.Name):
            if target.id == "_LIVE_ENGINES" and isinstance(node.value, ast.Dict):
                return [key.value for key in node.value.keys if isinstance(key, ast.Constant)]
    raise AssertionError("cyberai/cli/bench.py no longer defines _LIVE_ENGINES as a dict literal")


def _yaml_importers() -> list[pathlib.Path]:
    """Modules importing yaml at any nesting, which a grep for a column would miss."""
    importers = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            imported = isinstance(node, ast.Import) and any(
                alias.name.split(".")[0] == "yaml" for alias in node.names
            )
            from_yaml = (
                isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "yaml"
            )
            if imported or from_yaml:
                importers.append(path)
                break
    return importers


def test_the_page_counts_the_directories_the_manifest_lists() -> None:
    stated = _stated(r"The scope mixes two forms\. (\d+) directories are clean", "the directories")
    declared = _declared_directories()
    assert stated == len(declared), (
        f"the page says {stated} clean directories; [tool.mypy] files lists {declared}"
    )


def test_the_page_counts_the_tests_it_names() -> None:
    stated = _stated(r"(\d+) tests hold the pair above", "the pair of tests")
    named = sorted(set(re.findall(r"`(tests/architecture/\S+?\.py)`", _page())))
    assert stated == len(named), f"the page says {stated} tests hold the pair and names {named}"


def test_the_page_counts_the_factories_the_source_declares() -> None:
    stated = _stated(r"(\d+) factories in `_LIVE_ENGINES`", "the factories")
    keys = _live_engine_keys()
    assert stated == len(keys), f"the page says {stated} factories; _LIVE_ENGINES holds {keys}"


def test_the_page_counts_the_modules_that_import_yaml() -> None:
    stated = _stated(r"(\d+) modules import yaml", "the yaml importers")
    importers = [str(path.relative_to(_ROOT)) for path in _yaml_importers()]
    assert stated == len(importers), f"the page says {stated} importers of yaml; found {importers}"


def test_the_page_counts_the_rows_of_its_own_table() -> None:
    stated = _stated(r"(\d+) modules carry roughly a third", "the unchecked modules")
    rows = re.findall(r"^\| `(cyberai/\S+?\.py)` \| \d+ \|$", _page(), re.MULTILINE)
    assert stated == len(rows), f"the page says {stated} modules carry a third and tabulates {rows}"
