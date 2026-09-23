"""Every exception this package defines must be explained on the refusal page.

A refusal is a contract with whoever is at the screen. The tree holds ten of
them, spread across seven modules, and until this file existed not one was
named in docs/ or in the README -- ten ways the product says no, documented
nowhere. Prose does not rot loudly: a new exception lands in a module, the
page goes on listing the old set, and nothing disagrees out loud.

Both directions, for the reason the manifest guard states: a refusal the page
omits is a mechanism no reader can find, and a refusal the page names that
the tree no longer defines is the same rot left behind by a rename.

The set is collected structurally, not by suffix. A rule keyed on names
ending in Error or Violation reads the current tree correctly and would go
blind the day somebody writes `class Throttle(RuntimeError)` -- which is
exactly the edit this guard exists to catch. Inheritance is resolved through
locally defined classes as well, so a subclass of one of ours counts.

There is one collector, called twice: once over the package and once over a
sample where the structural rule and the name rule disagree. An earlier
revision had two copies, and mutation showed what that cost -- swapping the
package copy for a name test left every assertion green, because today's
tree happens to agree with both rules. A guard cannot hold a distinction its
own input never exercises.

The environment readers are checked the same way and for the same reason.
They are the other half of the page: six functions that refuse to invent a
choice rather than refusing to act, and the distinction between them is the
page's subject. A seventh reader added without a row would leave the page
describing a narrowing rule that no longer covers every variable.

What is not pinned is the wording. A test that pinned sentences would fail on
every edit to a paragraph and teach the reviewer to regenerate prose without
reading it.
"""

import ast
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PACKAGE = _ROOT / "cyberai"
_PAGE = _ROOT / "docs" / "architecture" / "refusal.md"

# Exception roots from the standard library. A class reaching any of these,
# directly or through one of ours, is a refusal.
_BUILTIN_ROOTS = frozenset(
    {
        "Exception",
        "BaseException",
        "RuntimeError",
        "ValueError",
        "TypeError",
        "KeyError",
        "OSError",
        "LookupError",
        "ArithmeticError",
    }
)

# The rule this guard is not allowed to be. Kept as a constant so the control
# below compares against it by name rather than by a second literal.
_NAME_RULE = ("Error", "Violation", "Exceeded", "Blocked", "Mismatch")

# The first cell of a markdown row when it is a single backticked token.
_ROW = re.compile(r"^\|\s*`([^`|]+)`\s*\|", re.MULTILINE)


def _is_exception(name: str, defined: dict[str, list[str]], seen: set[str]) -> bool:
    if name in _BUILTIN_ROOTS:
        return True
    if name in seen or name not in defined:
        return False
    seen.add(name)
    return any(_is_exception(base, defined, seen) for base in defined[name])


def _refusals_in(source: str) -> set[str]:
    """Every class in this source that reaches an exception root by inheritance."""
    defined: dict[str, list[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef):
            defined[node.name] = [ast.unparse(base) for base in node.bases]
    return {
        name
        for name, bases in defined.items()
        if any(_is_exception(base, defined, set()) for base in bases)
    }


def _tree_refusals() -> set[str]:
    """Every refusal the package defines, read from the tree on disk."""
    joined = "\n".join(path.read_text(encoding="utf-8") for path in sorted(_PACKAGE.rglob("*.py")))
    found = _refusals_in(joined)
    assert found, "no exceptions found in the package -- the walker broke"
    return found


def _env_readers() -> set[str]:
    """Every environment reader in the config module."""
    source = (_PACKAGE / "core" / "config.py").read_text(encoding="utf-8")
    found = {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name.startswith("_env_")
    }
    assert found, "no environment readers found -- the walker broke"
    return found


def _section(heading: str) -> str:
    """The body under one heading, up to the next one at any level."""
    lines = _PAGE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("#")),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _named_in(heading: str) -> set[str]:
    named = set(_ROW.findall(_section(heading)))
    assert named, f"the section {heading!r} holds no table"
    return named


def test_every_refusal_in_the_tree_is_explained_on_the_page() -> None:
    missing = _tree_refusals() - _named_in("## Every refusal in the tree")
    assert not missing, f"the tree raises what the page never explains: {sorted(missing)}"


def test_the_page_explains_no_refusal_the_tree_dropped() -> None:
    stale = _named_in("## Every refusal in the tree") - _tree_refusals()
    assert not stale, f"the page explains what the tree no longer defines: {sorted(stale)}"


def test_every_environment_reader_is_explained_on_the_page() -> None:
    missing = _env_readers() - _named_in("## Refusing to invent a choice")
    assert not missing, f"readers the page never explains: {sorted(missing)}"


def test_the_page_explains_no_reader_that_was_renamed() -> None:
    stale = _named_in("## Refusing to invent a choice") - _env_readers()
    assert not stale, f"the page explains readers that no longer exist: {sorted(stale)}"


def test_the_walker_reads_inheritance_and_not_the_name() -> None:
    """Control: on input where the two rules disagree, this collector is right.

    Every exception in the tree today ends in one of the five words above, so
    a guard keyed on suffixes passes every assertion here -- mutation
    confirmed it on 2026-09-23 by swapping the collector for a name test and
    watching the suite stay green. The rule is therefore asserted on input the
    package does not contain: a refusal named for what it is rather than for
    what it inherits, two generations of subclass, and a helper whose name
    ends in Error without being one.

    Three generations rather than two, measured on 2026-09-23. A collector
    that checked only the direct bases of a base still answered correctly at
    depth two -- asking about Deeper reaches Throttle, and Throttle's own
    bases hold RuntimeError -- so the recursion was not exercised by the
    shorter sample and a mutant that removed it survived. Depth three is the
    first input where a flat check and a recursive one disagree.

    This exercises the same function the four tests above call. A control
    running a second implementation would prove nothing about the first.
    """
    sample = (
        "class Throttle(RuntimeError):\n"
        "    pass\n"
        "class Deeper(Throttle):\n"
        "    pass\n"
        "class Deepest(Deeper):\n"
        "    pass\n"
        "class ReportsError:\n"
        "    pass\n"
    )
    found = _refusals_in(sample)
    assert found == {"Throttle", "Deeper", "Deepest"}, found

    by_name = {
        n for n in ("Throttle", "Deeper", "Deepest", "ReportsError") if n.endswith(_NAME_RULE)
    }
    assert by_name == {"ReportsError"}
    assert found != by_name, "the two rules agree on this input -- the control is dead"
