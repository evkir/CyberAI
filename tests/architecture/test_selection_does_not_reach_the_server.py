"""Choosing a target must not touch the target.

Selection reads registry metadata and asks GitHub whether a repository
answers. Reaching the MCP server the entry describes is a different act under
a different authorization, and the distinction is the whole reason this
command may run against entries nobody has given permission to test.

The guard is on the call graph rather than on the imports: a module that
imports nothing and builds a request inline would pass an import check and
still reach the server. Egress from these two modules is allowed through one
named function, and anything else is a finding here rather than in review.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_GUARDED = (
    _ROOT / "cyberai" / "agents" / "mcp_scan" / "registry.py",
    _ROOT / "cyberai" / "cli" / "registry_targets.py",
)

# The one sanctioned egress: git asking a host about refs. Everything that
# speaks to an MCP server, or opens a socket of its own, is named here so the
# guard fails on the call rather than on a import that may be indirect.
_FORBIDDEN_NAMES = frozenset(
    {
        "probe_auth_metadata",
        "urlopen",
        "create_connection",
        "ClientSession",
        "AsyncClient",
    }
)
# Verbs that are egress only when a client owns them. ``get`` on a dict parsed
# out of the registry dump is how this code reads metadata at all, so the guard
# asks who the receiver is rather than banning the word.
_FORBIDDEN_VERBS = frozenset({"get", "post", "head", "request", "connect", "Client"})
_FORBIDDEN_MODULES = frozenset(
    {"httpx", "requests", "urllib", "socket", "aiohttp", "mcp", "websockets"}
)
# Modules inside this package that speak to a server. Named by source rather
# than by the name a call site gives them: an alias renames the function, not
# where it came from, so a guard that reads names is one rename from blind.
_FORBIDDEN_SOURCES = ("cyberai.mcp.client_probe", "cyberai.mcp.auth_metadata")


def _root(node: ast.expr) -> str | None:
    """The leftmost name of an attribute chain: ``a`` in ``a.b.c()``."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _called_names(tree: ast.AST) -> set[str]:
    """Calls that reach out: bare egress names, plus verbs a client owns.

    An egress verb counts only when its receiver is a module this file
    imported. ``row.get("server")`` reads a parsed dump; ``httpx.get(url)``
    opens a connection, and the receiver is what tells them apart.
    """
    clients = _imported_modules(tree) & _FORBIDDEN_MODULES
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in _FORBIDDEN_NAMES:
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            if func.attr in _FORBIDDEN_NAMES:
                names.add(func.attr)
            elif func.attr in _FORBIDDEN_VERBS and _root(func) in clients:
                names.add(func.attr)
    return names


def _imported_sources(tree: ast.AST) -> set[str]:
    """Every module path this file imports from, spelled in full."""
    sources: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            sources.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            sources.add(node.module)
    return sources


def _imported_modules(tree: ast.AST) -> set[str]:
    """Top-level module names this module imports, however it spells them."""
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def test_selection_never_calls_into_a_server() -> None:
    for path in _GUARDED:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offending = _called_names(tree)
        assert offending == set(), (
            f"{path.relative_to(_ROOT)} calls {sorted(offending)}. Selection reads "
            "published metadata; connecting to the server an entry describes needs "
            "its owner's authorization and does not belong on this path."
        )


def test_selection_imports_from_no_module_that_speaks_to_a_server() -> None:
    """Named by source: an alias renames the call, not where it came from."""
    for path in _GUARDED:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offending = sorted(
            source for source in _imported_sources(tree) if source.startswith(_FORBIDDEN_SOURCES)
        )
        assert offending == [], (
            f"{path.relative_to(_ROOT)} imports from {offending}. Those modules "
            "connect to the server an entry describes, which needs its owner's "
            "authorization and does not belong on this path."
        )


def test_selection_pulls_in_no_client_of_its_own() -> None:
    for path in _GUARDED:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offending = _imported_modules(tree) & _FORBIDDEN_MODULES
        assert offending == set(), (
            f"{path.relative_to(_ROOT)} imports {sorted(offending)}. The only egress "
            "on this path is git asking a host about refs."
        )


def test_the_guard_would_notice() -> None:
    """A guard that cannot fail is a comment: show it failing on the real shape."""
    reaching = ast.parse("import httpx\nhttpx.get('https://example.invalid/mcp')\n")
    assert _called_names(reaching) == {"get"}
    assert _imported_modules(reaching) & _FORBIDDEN_MODULES == {"httpx"}

    # And the shape it must stay quiet about, or it would ban reading a dump.
    reading = ast.parse("row = {}\nrow.get('server')\n")
    assert _called_names(reading) == set()

    # The rename that defeats a name-based guard, which is why sources are read.
    aliased = ast.parse("from cyberai.mcp.client_probe import probe as p\np('x')\n")
    assert any(s.startswith(_FORBIDDEN_SOURCES) for s in _imported_sources(aliased))
