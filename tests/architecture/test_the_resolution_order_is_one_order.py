"""Every toolchain finder resolves an env override before it looks at PATH.

Eight functions locate an external binary and each was tested on its own, so
nothing compared them. The comparison is what was missing: no test set the
env variable and PATH at the same time, which means the precedence the
docstrings promise was never asserted anywhere -- and find_searchsploit had
no assertion of its own at all.

The set of finders is scanned out of the package rather than typed here, so a
ninth one cannot be added without either joining the registry or failing the
first assertion. A finder is a function named find_* whose body reaches for
shutil.which; find_escalation_paths shares the prefix and is excluded by that
rule, not by name.
"""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path
from unittest.mock import patch

import cyberai

# finder name -> (module, env variable the finder reads first)
REGISTRY = {
    "find_nuclei": ("cyberai.agents.exploit.nuclei_engine", "NUCLEI_PATH"),
    "find_searchsploit": ("cyberai.agents.exploit.searchsploit", "SEARCHSPLOIT_PATH"),
    "find_forge": ("cyberai.agents.web3.foundry_poc", "FORGE_PATH"),
    "find_aderyn": ("cyberai.agents.web3.aderyn_tool", "ADERYN_PATH"),
    "find_slither": ("cyberai.agents.web3.slither_tool", "SLITHER_PATH"),
    "find_anvil": ("cyberai.agents.web3.anvil_harness", "ANVIL_PATH"),
    "find_halmos": ("cyberai.agents.web3.halmos_tool", "HALMOS_PATH"),
    "find_mst": ("cyberai.agents.mcp_scan.mst_bridge", "MAS_SENTRY_PATH"),
}

_PACKAGE_ROOT = Path(cyberai.__file__).parent


def _reads_which(node: ast.FunctionDef) -> bool:
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "which"
            and isinstance(child.value, ast.Name)
            and child.value.id == "shutil"
        ):
            return True
    return False


def _scanned_finders() -> set[str]:
    found = set()
    for path in sorted(_PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef)
                and node.name.startswith("find_")
                and _reads_which(node)
            ):
                found.add(node.name)
    return found


def test_the_registry_names_exactly_the_finders_that_exist():
    scanned = _scanned_finders()
    assert not scanned - set(REGISTRY), f"finders outside the registry: {scanned - set(REGISTRY)}"
    assert not set(REGISTRY) - scanned, f"registry names no such finder: {set(REGISTRY) - scanned}"


def test_every_finder_prefers_the_env_override_over_path(tmp_path, monkeypatch):
    for name, (module_path, variable) in REGISTRY.items():
        module = importlib.import_module(module_path)
        override = tmp_path / name
        override.write_text("#!/bin/sh\n")
        monkeypatch.setenv(variable, str(override))
        with patch.object(module.shutil, "which", return_value=f"/decoy/{name}"):
            resolved = getattr(module, name)()
        assert resolved == str(override), f"{name} read PATH before {variable}"


# Each source a finder can read, and the word its docstring uses for it. PATH
# is matched on a word boundary so that MAS_SENTRY_PATH does not read as the
# search path.
_SOURCES = {"env": r"\benv\b", "which": r"\bPATH\b", "fallback": r"\bfallback\b"}


def _finder_node(module_path: str, name: str) -> ast.FunctionDef:
    path = _PACKAGE_ROOT.parent / (module_path.replace(".", "/") + ".py")
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in {module_path}")


def _body_order(node: ast.FunctionDef) -> list[str]:
    seen: dict[str, tuple[int, int]] = {}
    for child in ast.walk(node):
        source = None
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
            if child.value.id == "os" and child.attr == "getenv":
                source = "env"
            elif child.value.id == "shutil" and child.attr == "which":
                source = "which"
        elif isinstance(child, ast.Name) and child.id == "_FALLBACK_PATHS":
            source = "fallback"
        if source is not None:
            here = (child.lineno, child.col_offset)
            if source not in seen or here < seen[source]:
                seen[source] = here
    return [s for s, _ in sorted(seen.items(), key=lambda kv: kv[1])]


def _docstring_order(node: ast.FunctionDef) -> list[str]:
    text = ast.get_docstring(node) or ""
    found = {}
    for source, pattern in _SOURCES.items():
        match = re.search(pattern, text)
        if match:
            found[source] = match.start()
    return [s for s, _ in sorted(found.items(), key=lambda kv: kv[1])]


def test_every_docstring_names_the_sources_its_body_reads():
    """A source reached but unnamed, or named but unreached, is a wrong promise."""
    for name, (module_path, _) in REGISTRY.items():
        node = _finder_node(module_path, name)
        assert set(_docstring_order(node)) == set(_body_order(node)), (
            f"{name}: docstring names {set(_docstring_order(node))}, "
            f"body reads {set(_body_order(node))}"
        )


def test_every_docstring_names_them_in_the_order_the_body_reads_them():
    """find_nuclei promised PATH first and read the env override first."""
    for name, (module_path, _) in REGISTRY.items():
        node = _finder_node(module_path, name)
        assert _docstring_order(node) == _body_order(node), (
            f"{name}: docstring says {_docstring_order(node)}, body does {_body_order(node)}"
        )
