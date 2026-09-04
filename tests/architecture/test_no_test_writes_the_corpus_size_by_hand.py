"""The corpus supplies its own size, everywhere but the one pin that wants it.

Adding two samples turned two assertions false in files that had nothing to
do with the corpus. Both wrote a tally as a digit -- "TP 49", true_positive
== 49 -- so they measured how many samples happened to be tracked rather
than the code they were named after, and neither was found by reasoning
about the change. They were found by running everything afterwards, in a
commit that had already been made.

So a tally compared against a non-zero literal, inside a test that loads the
tracked corpus, fails here. Zero is left alone deliberately: "no false
positives" is a claim about the detector and stays true at any corpus size,
while any non-zero tally is a count of samples wearing another name.

One test is allowed to write those numbers, and it is the one whose whole
purpose is to fail when they move. The allowance is declared rather than
inferred, and it is checked in both directions: an entry naming a function
that does not exist is a stale exemption, and an entry whose function no
longer writes such a literal is an exemption with nothing behind it.
"""

import ast
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_TESTS = _ROOT / "tests"

_TALLIES = {"true_positive", "false_negative", "true_negative", "false_positive"}
_RENDERED = re.compile(r"\b(TP|FN|TN|FP) (\d+)")

# The one test whose job is to fail when these numbers move, so it states
# them. Everything else derives them.
_ALLOWED = {
    (
        "tests/unit/test_eval_corpus.py",
        "test_the_tracked_corpus_reproduces_the_published_baseline",
    ),
}


def _functions() -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    out = []
    for path in sorted(_TESTS.rglob("*.py")):
        if "corpus" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken test file is another gate's finding
            continue
        rel = path.relative_to(_ROOT).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append((rel, node))
    return out


def _reads_the_tracked_corpus(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "load_corpus":
            return True
        if isinstance(node, ast.Name) and node.id == "CORPUS":
            return True
    return False


def _hand_written_tallies(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and len(node.comparators) == 1:
            right = node.comparators[0]
            if isinstance(right, ast.Constant) and isinstance(right.value, int) and right.value:
                subject = {n.attr for n in ast.walk(node.left) if isinstance(n, ast.Attribute)}
                subject |= {
                    n.value
                    for n in ast.walk(node.left)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                }
                if subject & _TALLIES:
                    found.append(f"line {node.lineno}: == {right.value}")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for tag, digits in _RENDERED.findall(node.value):
                if int(digits):
                    found.append(f"line {node.lineno}: {tag} {digits}")
    return found


def test_no_test_states_a_tally_the_corpus_could_have_told_it() -> None:
    offenders = []
    for rel, fn in _functions():
        if (rel, fn.name) in _ALLOWED or not _reads_the_tracked_corpus(fn):
            continue
        offenders += [(rel, fn.name, hit) for hit in _hand_written_tallies(fn)]
    assert not offenders, (
        f"tally written by hand in a test that loads the corpus: {offenders}. "
        "Take the number from load_corpus instead."
    )


def test_every_allowance_names_a_test_that_exists() -> None:
    known = {(rel, fn.name) for rel, fn in _functions()}
    stale = sorted(_ALLOWED - known)
    assert not stale, f"allowance for a test that is gone: {stale}"


def test_every_allowance_is_covering_something() -> None:
    """An exemption with nothing behind it is a rule nobody is following."""
    idle = sorted(
        (rel, fn.name)
        for rel, fn in _functions()
        if (rel, fn.name) in _ALLOWED and not _hand_written_tallies(fn)
    )
    assert not idle, f"allowance covering no hand-written tally: {idle}; drop it"
