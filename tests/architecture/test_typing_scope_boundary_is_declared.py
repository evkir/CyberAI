"""The typing scope has an edge, and until now nothing said where.

`[tool.mypy] files` resolves to 107 modules and the run reports `Success` on
exactly 107, which reads like a guarantee about those modules and is one only
up to the boundary. Twenty-two of them import a module outside the scope at
module level. Both numbers were 95 and 19 when this was written and are
restated here on 2026-09-23; the assertions below are what holds them. mypy follows such an import to resolve the name and stays silent about
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
# 2026-09-20: cyberai/core/config.py entered the scope, so the modules
# whose only crossing was that import stopped crossing, and config.py
# left the reached set as well: 22 reaching 29 became 20 reaching 28.
# The counts fell because the edge moved, not because an import did.
# 2026-09-20, same day: cyberai/__main__.py and cyberai/core/model_router.py
# were declared, and the counts rose to 22 reaching 31. A module entering
# the scope brings its own imports to the edge, so declaring one moves both
# counts and the direction depends on which side of the import it sits.
# __main__.py reaches three modules nothing else in the scope reaches:
# cli/audit_verify.py, cli/detector_eval.py, cli/scope.py.
# 2026-09-23: immunefi_severity.py, bench/apps/_server.py and
# core/exploit_memory.py were declared, priced at zero on both counters by
# scripts/scope_price.py before the fact and moving neither afterwards.
# Third move the same day: agents/exploit/safety_validator.py was declared,
# and only reached fell, 31 to 30. It imports nothing outside the scope, so
# it never became a crosser; it stopped being reached. A leaf costs one
# counter, an entry point costs both.
# 2026-10-01: integrations/phantom_grid.py was declared, priced at -2 and -1
# by scripts/scope_price.py before the fact and moving both counters by
# exactly that afterwards: 20 reaching 28 became 18 reaching 27. Two modules
# crossed only to reach it, so both stopped crossing, and it imports nothing
# outside the scope, so it joined no crossing of its own.
# 2026-10-01, same day: bench/docker_builder.py was declared, priced at -1 and
# -1 and moving both by that: 18 reaching 27 became 17 reaching 26. Three
# modules import it, two of them inside the scope, and only one stopped
# crossing -- the other reaches past the edge elsewhere as well. Both modules
# declared today so far were independent of one another, so their prices
# summed; that is a fact about these two, not a rule about any two.
# 2026-10-01, third today: core/base_agent.py was declared, priced at -1 and
# -1 and moving both by that: 17 reaching 26 became 16 reaching 25. Ten
# modules import it and five of those are inside the scope, yet the crosser
# count falls by one: the other four reach past the edge elsewhere too. The
# same day web/app.py was priced and left alone -- one error, +1 crosser and
# +5 reached, which is the pair this rule exists to make visible before the
# fact rather than after.
_EXPECTED_CROSSERS = 16
_EXPECTED_REACHED = 25


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
    assert len(_scope()) == 112
    assert len(list(_PACKAGE.rglob("*.py"))) == 172


def test_the_edge_of_the_scope_is_where_the_prose_says_it_is() -> None:
    """Both counts, so an import removed and one added do not cancel out."""
    crossers, reached = _crossings()
    assert len(crossers) == _EXPECTED_CROSSERS, sorted(str(m.relative_to(_ROOT)) for m in crossers)
    assert len(reached) == _EXPECTED_REACHED, sorted(str(m.relative_to(_ROOT)) for m in reached)
