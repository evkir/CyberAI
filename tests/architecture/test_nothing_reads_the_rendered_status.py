"""No test asserts against the rendered status panel; it reads what was built.

Two assertions moved off the render in September, the rest of the panel in
this branch. Both were migrations, and a migration is a fact about the tree on
one day: nothing stopped the next test from calling the command and matching a
substring of its output again. The risk this file removes is not the tests
that were fixed, it is the one that would have been written next.

Rich lays the panel out at the console width, and the found half of the
toolchain line is one comma-separated run over whichever binaries resolve on
the host, so the wrap point is a fact about the operator's PATH. An assertion
matched against the render therefore passes or fails by the machine: the same
tree came out green where a tool was missing and red where the toolchain was
complete. _status_body returns those lines before anything renders them, and
the panel is held to displaying that result by
test_the_readme_names_what_status_prints.

The condition of an assertion is read, never its message.
`assert result.exit_code == 0, result.output` asserts nothing about the text
and prints the panel when the exit code is wrong; forbidding it would move the
diagnostic out of the test that needs it. That distinction is planted below,
so a rule that stops making it fails here rather than in review.

What this does not cover, measured rather than assumed: the command is
recognised by a literal argv whose first element is "status", so a call
assembled into a variable first is invisible. No such call exists in this tree
-- every status invocation passes its list inline -- and the floor below
fails if the walk stops finding the ones that do. Commands other than status
are out of scope on purpose: the bench suite reads its rendered table in 48
assertions, which is the same class under another command and a separate
piece of work, not something to half-forbid here.
"""

from __future__ import annotations

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_TESTS = _ROOT / "tests"

# Attributes that hand back text Rich has already laid out.
_RENDERED = frozenset({"output", "stdout", "stderr"})

# Two status invocations remain in this tree, both asserting the exit code of
# the command rather than its text. The floor equals the measurement because at
# two the only slack left is zero, and zero means the walk broke rather than
# that the suite changed.
_STATUS_CALL_FLOOR = 2


def _is_status_invoke(call: ast.Call) -> bool:
    """A CliRunner invocation whose argv literal starts with "status"."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "invoke"):
        return False
    if len(call.args) < 2 or not isinstance(call.args[1], ast.List):
        return False
    argv = call.args[1].elts
    head = argv[0] if argv else None
    return isinstance(head, ast.Constant) and head.value == "status"


def _defined(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Functions of a test module, including methods, excluding nested ones.

    A nested helper walked as a function of its own would count its parent's
    invocation twice and move the floor for no reason.
    """
    out: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(node)
        elif isinstance(node, ast.ClassDef):
            out.extend(
                b for b in node.body if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
    return out


def scan(root: pathlib.Path) -> tuple[set[tuple[str, str, str]], int]:
    """Assertions reading the rendered status output, and status calls seen."""
    violations: set[tuple[str, str, str]] = set()
    calls = 0
    for path in sorted((root / "tests").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(root).as_posix()
        for fn in _defined(tree):
            invocations = [
                n for n in ast.walk(fn) if isinstance(n, ast.Call) and _is_status_invoke(n)
            ]
            if not invocations:
                continue
            calls += len(invocations)
            for node in ast.walk(fn):
                if not isinstance(node, ast.Assert):
                    continue
                for inner in ast.walk(node.test):
                    if isinstance(inner, ast.Attribute) and inner.attr in _RENDERED:
                        violations.add((rel, fn.name, ast.unparse(node.test)[:70]))
                        break
    return violations, calls


def _plant(root: pathlib.Path) -> None:
    """A suite holding one read of each form, and one legal use of the panel."""
    suite = root / "tests"
    suite.mkdir(parents=True)
    (suite / "test_planted.py").write_text(
        "from click.testing import CliRunner\n"
        "\n"
        "from cyberai.__main__ import cli\n"
        "\n"
        "\n"
        "def test_reads_through_a_name():\n"
        "    result = CliRunner().invoke(cli, ['status'])\n"
        "    assert 'Provider' in result.output\n"
        "\n"
        "\n"
        "def test_reads_inline():\n"
        "    assert 'P' in CliRunner().invoke(cli, ['status', '--versions']).output\n"
        "\n"
        "\n"
        "def test_reports_the_panel_in_the_message():\n"
        "    result = CliRunner().invoke(cli, ['status'])\n"
        "    assert result.exit_code == 0, result.output\n",
        encoding="utf-8",
    )


def test_no_test_asserts_against_the_rendered_status() -> None:
    violations, _ = scan(_ROOT)
    assert violations == set(), (
        "these assertions match a substring of the rendered panel, whose wrap "
        "point is decided by the console width and the installed toolchain; "
        "read cyberai.__main__._status_body instead: " + repr(sorted(violations))
    )


def test_the_walk_still_finds_the_status_calls() -> None:
    """A walk that finds no invocation reports no violation and looks clean."""
    _, calls = scan(_ROOT)
    assert calls >= _STATUS_CALL_FLOOR, (
        f"only {calls} status invocations were found; the walk is broken, not the suite"
    )


def test_a_planted_read_of_each_form_is_caught(tmp_path: pathlib.Path) -> None:
    """The rule is measured against known-bad input, not trusted on silence.

    The third planted function is the control: it puts the panel in the
    message of an exit-code assertion, which is legal, so a rule that reads
    whole assertions rather than their conditions fails here.
    """
    _plant(tmp_path)
    violations, calls = scan(tmp_path)
    assert calls == 3, calls
    assert {(path, name) for path, name, _ in violations} == {
        ("tests/test_planted.py", "test_reads_through_a_name"),
        ("tests/test_planted.py", "test_reads_inline"),
    }, sorted(violations)
