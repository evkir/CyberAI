"""An empty tool list means two different things and the probe does not say which.

`_dump` swallows the exception a target raises for a capability it does not
implement and returns `[]`. The comment above it says so, and for that case it
is right. The same line also swallows a `tools/list` that failed on a server
that does have tools: a timeout, a transport error, a response the SDK could
not parse. `result.error` is only written when the outer `try` in `probe`
catches, which that path does not reach, so both outcomes leave the caller
`connected=True`, `error=None`, `tools=[]`.

Four stages key off that list -- poisoning, overprivilege, trust, instructions
-- and each reads it as the surface the server advertises. The instructions
stage is the one where it changed a verdict: the unconditional pair went
vacuous and convicted a server of documenting itself, which is why the pair is
now scoped to a sentence. The other three read an empty list as a clean
server, which is the same confusion with a quieter result.

This file does not fix the ambiguity; a fix changes `_dump`'s signature and
four consumers. It pins that the ambiguity is real, so a change to it is a
change someone made on purpose. When `_dump` learns to distinguish them, these
assertions are what should red.
"""

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PROBE = _ROOT / "cyberai" / "mcp" / "client_probe.py"


def _function(name: str) -> ast.AST:
    tree = ast.parse(_PROBE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name} is not in {_PROBE.name}")


def test_the_dump_reports_nothing_about_why_it_is_empty() -> None:
    """The handler returns a bare list and writes no diagnostic anywhere."""
    dump = _function("_dump")
    handlers = [n for n in ast.walk(dump) if isinstance(n, ast.ExceptHandler)]
    assert handlers, "_dump no longer swallows anything; the ambiguity may be gone"

    for handler in handlers:
        assigned = [n for n in ast.walk(handler) if isinstance(n, (ast.Assign, ast.AugAssign))]
        assert not assigned, (
            "_dump now records something about the failure -- if it distinguishes "
            "an unsupported capability from a failed read, the four consumers of "
            "an empty surface need to be taught the difference"
        )


def test_a_failed_inventory_does_not_reach_the_result_error() -> None:
    """`error` is written in `probe`'s own handler, which this path skips."""
    probe = _function("probe")
    writes = {
        ast.unparse(target)
        for node in ast.walk(probe)
        if isinstance(node, ast.Assign)
        for target in node.targets
    }
    assert "result.error" in writes, "probe no longer records an error at all"
    assert "result.tools" in writes

    handler_writes = {
        ast.unparse(target)
        for handler in (n for n in ast.walk(probe) if isinstance(n, ast.ExceptHandler))
        for node in ast.walk(handler)
        if isinstance(node, ast.Assign)
        for target in node.targets
    }
    assert handler_writes == {"result.error"}, (
        "the only thing probe's handler records is the error; an inventory that "
        "failed inside _dump never arrives here"
    )


def test_the_instructions_are_read_before_the_surface_is() -> None:
    """Why the pair saw text with no tools: the assignments are in this order."""
    probe = _function("probe")
    order = [
        ast.unparse(target)
        for node in ast.walk(probe)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if ast.unparse(target) in {"result.instructions", "result.tools"}
    ]
    assert order == ["result.instructions", "result.tools"], order
