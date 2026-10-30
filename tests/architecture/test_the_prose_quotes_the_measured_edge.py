"""The prose beside a measured count must quote that count.

`test_typing_scope_boundary_is_declared.py` holds two numbers against the
tree and reds when either moves. What it does not do is read the page. A
move therefore reds there, the constant gets rewritten by whoever moved it,
and the sentence in docs/architecture/typing-scope.md that states the same
two numbers stays behind -- green, silent and wrong. Three numbers on that
page drifted exactly that way before anyone noticed.

The direction of this check is the opposite of the one next door, and that
is deliberate. There the tree is the standard and the prose is not read, so
the test cannot agree with itself. Here the constant is the standard and the
prose is what is checked, which is sound only because the constant is itself
held against the tree by that other test. Remove it and this one measures
nothing.

Dated counts are out of reach on purpose. A sentence that says when it was
measured is a record, not a claim about today, and pinning one would red on
every release of the checker.
"""

import importlib.util
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PAGE = _ROOT / "docs" / "architecture" / "typing-scope.md"
_NEIGHBOUR = _ROOT / "tests" / "architecture" / "test_typing_scope_boundary_is_declared.py"


def _neighbour_constants() -> tuple[int, int]:
    spec = importlib.util.spec_from_file_location("_boundary_guard", _NEIGHBOUR)
    assert spec is not None and spec.loader is not None, f"cannot load {_NEIGHBOUR}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return int(module._EXPECTED_CROSSERS), int(module._EXPECTED_REACHED)


_CURRENT = re.compile(
    r"(\d+) import a module outside it at module level,\s*\n"
    r"and between them they reach (\d+) such modules"
)


def test_the_page_states_the_edge_in_one_undated_sentence() -> None:
    """One match, so a second phrasing cannot drift unseen behind the first."""
    found = _CURRENT.findall(_PAGE.read_text(encoding="utf-8"))
    assert len(found) == 1, f"the page states the current edge {len(found)} times, not once"


def test_the_page_quotes_the_edge_the_neighbour_holds() -> None:
    found = _CURRENT.search(_PAGE.read_text(encoding="utf-8"))
    assert found, "the page no longer states the edge in the form this guard reads"
    quoted = (int(found.group(1)), int(found.group(2)))
    assert quoted == _neighbour_constants(), (
        f"the page says {quoted} while the guard beside it holds {_neighbour_constants()}"
    )


def test_the_page_names_tests_that_exist() -> None:
    """The page points the reader at two files by path.

    A renamed or deleted guard leaves the sentence pointing at nothing, and
    the reader who follows it finds out before the page does. The earlier
    wording said "the test named below" and named none, which is the same
    break with nothing to check it against.
    """
    named = re.findall(r"`(tests/architecture/\S+?\.py)`", _PAGE.read_text(encoding="utf-8"))
    assert named, "the page names no guard for the counts it states"
    missing = [path for path in named if not (_ROOT / path).is_file()]
    assert not missing, f"the page names guards that do not exist: {missing}"


def test_the_neighbour_prose_quotes_its_own_constants() -> None:
    """The guard's own docstring states the counts and drifted away from them."""
    crossers, _ = _neighbour_constants()
    head = _NEIGHBOUR.read_text(encoding="utf-8").split('"""')[1]
    match = re.search(r"(\d+) of them import a module outside the scope", head)
    assert match, "the guard's docstring no longer states its crosser count in digits"
    assert int(match.group(1)) == crossers, (
        f"the docstring says {match.group(1)} crossers while the constant holds {crossers}"
    )
