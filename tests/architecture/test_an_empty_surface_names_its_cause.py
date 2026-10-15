"""An empty capability list must say which of its causes produced it.

`_dump` returns `[]` for three different reasons: the server answered
METHOD_NOT_FOUND and has nothing to show, the read failed on a server that may
have a surface, or this client's pagination call did not match the SDK
signature. Only the first is a measurement. Six consumers read the tool list --
the probed-tool count, poisoning, overprivilege, exposure, trust, instructions
-- and a failed read scored as a clean server is a verdict about something
nobody looked at.

The previous version of this file asserted the ambiguity was still there, by
checking that `_dump`'s handler assigned nothing. That shape was too narrow: a
handler can report a cause by returning one, which is what it now does, so the
assertions passed through the fix they were meant to catch. These assert the
distinction exists and reaches the result instead.
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


def test_the_dump_hands_back_a_cause_beside_the_items() -> None:
    """Every exit from `_dump` is a pair, so no caller can read items alone."""
    dump = _function("_dump")
    returns = [n for n in ast.walk(dump) if isinstance(n, ast.Return)]
    assert returns, "_dump returns nothing"
    for node in returns:
        assert isinstance(node.value, ast.Tuple), (
            f"_dump returns a bare value at line {node.lineno}; an empty list "
            "without its cause is the ambiguity this file exists to prevent"
        )
        assert len(node.value.elts) == 2


def test_the_handler_tells_an_unsupported_capability_from_a_failed_read() -> None:
    """The branch on the JSON-RPC code is what separates the two."""
    dump = _function("_dump")
    handlers = [n for n in ast.walk(dump) if isinstance(n, ast.ExceptHandler)]
    assert handlers, "_dump no longer swallows anything"
    source = "\n".join(ast.unparse(h) for h in handlers)
    assert "_METHOD_NOT_FOUND" in source, (
        "the handler no longer branches on the method-not-found code, so a "
        "server with no capability and a server that failed to answer are "
        "once again the same empty list"
    )


def test_the_cause_reaches_the_result() -> None:
    """`probe` records the causes on a field of its own, beside `error`."""
    probe = _function("probe")
    writes = {
        ast.unparse(target)
        for node in ast.walk(probe)
        if isinstance(node, ast.Assign)
        for target in node.targets
    }
    assert "result.surface_errors" in writes, (
        "probe drops the causes inventory_with_causes returns; the consumers "
        "cannot tell an unmeasured surface from an empty one"
    )
    assert "result.error" in writes
    assert "result.tools" in writes


def test_the_instructions_are_read_before_the_surface_is() -> None:
    """Why the unconditional pair saw text with no tools (JI)."""
    probe = _function("probe")
    order = [
        ast.unparse(target)
        for node in ast.walk(probe)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if ast.unparse(target) in {"result.instructions", "result.tools"}
    ]
    assert order == ["result.instructions", "result.tools"], order
