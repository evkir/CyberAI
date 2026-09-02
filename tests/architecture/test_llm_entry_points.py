"""No fifth way into a provider can appear without the guard.

tests/unit/test_llm_chokepoint.py already names all four entry points and
drives each one through a real call. That is the stronger evidence for the
four that exist, and it is deliberately not repeated here.

What a named list cannot do is cover the entry point nobody has written
yet. Its own docstring records the miss: an earlier pass found three and
missed structured_call. So this file states the invariant structurally --
any public LLMClient method taking `messages` calls _guard -- which a new
method satisfies or fails on the day it is added.
"""

import ast
import pathlib

CLIENT_SOURCE = pathlib.Path(__file__).resolve().parents[2] / "cyberai" / "core" / "llm_client.py"


def _public_message_methods():
    tree = ast.parse(CLIENT_SOURCE.read_text(encoding="utf-8"))
    cls = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LLMClient"
    )
    for member in cls.body:
        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if member.name.startswith("_"):
            continue
        params = [a.arg for a in member.args.args] + [a.arg for a in member.args.kwonlyargs]
        if "messages" in params:
            yield member


def _calls_in(node) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, (ast.Name, ast.Attribute)):
            names.add(child.func.id if isinstance(child.func, ast.Name) else child.func.attr)
    return names


def test_every_entry_point_taking_messages_consults_the_guard():
    unguarded = [m.name for m in _public_message_methods() if "_guard" not in _calls_in(m)]
    assert not unguarded, (
        f"public LLMClient methods that take messages but skip _guard: {unguarded}"
    )


def test_the_rule_is_not_vacuous():
    """A rule matching nothing passes forever. Four entry points exist today."""
    found = sorted(m.name for m in _public_message_methods())
    assert found == ["acall", "call", "call_tools", "structured_call"]
