"""Every third-party module the package imports is declared in pyproject.

A dependency that the code imports but the manifest omits installs by accident:
it arrives transitively today and disappears the day the graph shifts. That is
how requirements.txt shipped an environment without mcp, cryptography, fastapi,
uvicorn and pyyaml while every test stayed green -- the second install line
covered for it.

Written as an inversion, like test_sandbox_sealing: scanning the whole package
means new code importing a new library fails here by default. A hand-kept list
would be a reminder, not a barrier.

importlib.metadata.packages_distributions() is deliberately NOT used. On this
machine cryptography 46.0.5 is the Debian system package: its dist-info carries
no file list and no top_level.txt, so the mapping silently omits it and the
check would report a declared dependency as missing. The alias table below is
tiny, explicit, and its own drift is caught by test_declared_aliases_resolve.

Paths are anchored to this file: the suite runs from a scratch directory.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_PACKAGE = _ROOT / "cyberai"
_MANIFEST = _ROOT / "pyproject.toml"

# import root -> distribution name on PyPI. Only entries where the two differ.
_ALIASES = {
    "dns": "dnspython",
    "dotenv": "python-dotenv",
    "whois": "python-whois",
    "yaml": "pyyaml",
}


def _normalize(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _declared() -> set[str]:
    raw = tomllib.loads(_MANIFEST.read_text(encoding="utf-8"))
    out = set()
    for spec in raw["project"]["dependencies"]:
        head = spec.split(">")[0].split("<")[0].split("=")[0].split("[")[0]
        out.add(_normalize(head))
    return out


def _is_internal(root: str) -> bool:
    """True when the root resolves to a file or package inside cyberai/.

    bench/apps modules fall back to ``from _server import ...`` so they can run
    as scripts inside the bench container; that root is ours, not a library.
    """
    if root == "cyberai":
        return True
    for path in _PACKAGE.rglob(root):
        if path.is_dir() and (path / "__init__.py").exists():
            return True
    return any(_PACKAGE.rglob(f"{root}.py"))


def _import_roots() -> dict[str, list[str]]:
    """Map every top-level import root in the package to its call sites."""
    roots: dict[str, list[str]] = {}
    for file in sorted(_PACKAGE.rglob("*.py")):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level or not node.module:
                    continue
                names = [node.module]
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                site = f"{file.relative_to(_ROOT)}:{node.lineno}"
                roots.setdefault(root, []).append(site)
    return roots


def test_every_imported_library_is_declared():
    """No module may import a library the manifest does not install."""
    declared = _declared()
    undeclared = {}
    for root, sites in _import_roots().items():
        if root in sys.stdlib_module_names or _is_internal(root):
            continue
        if _normalize(_ALIASES.get(root, root)) not in declared:
            undeclared[root] = sites[:3]
    assert not undeclared, f"imported but not in pyproject dependencies: {undeclared}"


def test_declared_aliases_resolve():
    """An alias naming a distribution nobody declares is stale bookkeeping."""
    declared = _declared()
    stale = {root: dist for root, dist in _ALIASES.items() if _normalize(dist) not in declared}
    assert not stale, f"alias points at an undeclared distribution: {stale}"


def test_the_repository_declares_dependencies_in_one_place():
    """A second manifest drifts: requirements.txt lost five packages silently."""
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=_ROOT, check=True
    ).stdout.split()
    manifests = [
        p for p in tracked if Path(p).name in {"requirements.txt", "setup.py", "setup.cfg"}
    ]
    assert not manifests, f"dependencies must live in pyproject.toml alone, found: {manifests}"
