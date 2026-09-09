"""The typing scope has an edge, and until now nothing said where.

`[tool.mypy] files` names 95 modules and the run reports `Success` on exactly
95, which reads like a guarantee about those modules and is one only up to
the boundary. Nineteen of them import a module outside the scope at module
level. mypy follows such an import to resolve the name and stays silent about
what it finds: appending an unannotated function to `cyberai/core/config.py`,
which is outside the scope and imported from inside it, changed nothing about
the output on a cold cache. A name crossing the edge is therefore typed by a
module nothing checks.

That is a fact about the shape of the codebase, not a defect to repair, and
this file does not ask for it to shrink. It asks for it to be known. The two
counts move when an import is added or removed across the edge, and moving
them reds here, so the paragraph in docs/architecture/typing-scope.md gets
rewritten by whoever moved them rather than by whoever notices years later.

The counts are deliberately not derived from the doc. Reading them out of the
prose they exist to check would make this test agree with itself.
"""

import ast
import pathlib
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PACKAGE = _ROOT / "cyberai"

# Measured on the day this file was written, with the method below.
_EXPECTED_CROSSERS = 21
_EXPECTED_REACHED = 28


def _scope() -> set[pathlib.Path]:
    config = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared: set[pathlib.Path] = set()
    for entry in config["tool"]["mypy"]["files"]:
        path = _ROOT / entry
        if path.is_dir():
            declared.update(path.rglob("*.py"))
        else:
            declared.add(path)
    return declared


def _resolve(dotted: str) -> pathlib.Path | None:
    base = _ROOT / pathlib.Path(dotted.replace(".", "/"))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.exists():
            return candidate
    return None


def _imported_names(module: pathlib.Path) -> list[str]:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package = module.parent
                for _ in range(node.level - 1):
                    package = package.parent
                dotted = str(package.relative_to(_ROOT)).replace("/", ".")
                if node.module:
                    dotted = f"{dotted}.{node.module}"
            else:
                dotted = node.module or ""
            names.append(dotted)
            names.extend(f"{dotted}.{alias.name}" for alias in node.names)
    return names


def _crossings() -> tuple[set[pathlib.Path], set[pathlib.Path]]:
    declared = _scope()
    crossers: set[pathlib.Path] = set()
    reached: set[pathlib.Path] = set()
    for module in sorted(declared):
        for dotted in _imported_names(module):
            if not dotted.startswith("cyberai"):
                continue
            target = _resolve(dotted)
            if target is not None and target not in declared:
                crossers.add(module)
                reached.add(target)
    return crossers, reached


def test_the_scope_covers_the_modules_it_declares() -> None:
    """The premise the rest of this file argues about."""
    assert len(_scope()) == 98
    assert len(list(_PACKAGE.rglob("*.py"))) == 171


def test_the_edge_of_the_scope_is_where_the_prose_says_it_is() -> None:
    """Both counts, so an import removed and one added do not cancel out."""
    crossers, reached = _crossings()
    assert len(crossers) == _EXPECTED_CROSSERS, sorted(str(m.relative_to(_ROOT)) for m in crossers)
    assert len(reached) == _EXPECTED_REACHED, sorted(str(m.relative_to(_ROOT)) for m in reached)
