#!/usr/bin/env python3
"""What a module costs before it is added to `[tool.mypy] files`.

Three times on 2026-09-21 the boundary counters moved as modules entered the
scope, and three times the expected numbers in the guard were corrected after
the fact by rerunning it and reading the failure. That works and teaches
nothing: the price was paid first and read afterwards. The prose on the scope
page states the rule -- a leaf pays one counter, an entry point pays both --
and the rule was written from those three moves rather than measured against
a fourth.

This reads the price first. For a candidate module it reports the errors the
module itself brings under the declared flags, and the two boundary counters
as they would stand with the module inside the scope. Nothing in the tree is
edited to get there: the scoped run is driven by a config file written to a
temporary directory, so `pyproject.toml` is never touched and an interrupted
run leaves no half-applied scope behind.

The counters are counted the way the guard counts them, from the import graph
rather than from the checker, because that is the measurement the guard will
compare against. A number produced by a different method would agree with the
guard by luck and diverge without warning.

A run that produces no verdict line is not a clean module. `mypy` absent from
the environment writes nothing to standard output, and every count taken from
that silence reads as zero errors on a module nobody checked.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_PACKAGE = _ROOT / "cyberai"

_ERROR = re.compile(r"^(?P<module>[^:]+\.py):\d+: error")
_VERDICT = re.compile(r"^(Found \d+ error|Success: no issues found)", re.MULTILINE)


def settings() -> dict[str, object]:
    loaded: dict[str, object] = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["tool"][
        "mypy"
    ]
    return loaded


def declared_scope(config: dict[str, object]) -> set[pathlib.Path]:
    declared = config["files"]
    if not isinstance(declared, list):
        raise TypeError("[tool.mypy] files is not a list; the scope cannot be resolved")
    resolved: set[pathlib.Path] = set()
    for entry in declared:
        path = _ROOT / str(entry)
        if path.is_dir():
            resolved.update(path.rglob("*.py"))
        else:
            resolved.add(path)
    return resolved


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


def crossings(declared: set[pathlib.Path]) -> tuple[set[pathlib.Path], set[pathlib.Path]]:
    """Modules importing past the edge, and the modules they reach."""
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


def _config_text(config: dict[str, object], files: list[str]) -> str:
    lines = ["[tool.mypy]"]
    for key in ("python_version", "strict", "ignore_missing_imports"):
        if key not in config:
            continue
        value = config[key]
        if isinstance(value, bool):
            lines.append(f"{key} = {str(value).lower()}")
        else:
            lines.append(f'{key} = "{value}"')
    lines.append("files = [")
    lines.extend(f'    "{entry}",' for entry in files)
    lines.append("]")
    return "\n".join(lines) + "\n"


def run_scoped(config: dict[str, object], files: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the checker over an arbitrary file set without editing the tree."""
    with tempfile.TemporaryDirectory() as tmp:
        written = pathlib.Path(tmp) / "mypy.toml"
        written.write_text(_config_text(config, files), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "mypy",
                "--config-file",
                str(written),
                "--cache-dir",
                str(pathlib.Path(tmp) / "cache"),
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )


def errors_in(output: str, module: pathlib.Path) -> int:
    relative = module.relative_to(_ROOT).as_posix()
    return sum(
        1
        for line in output.splitlines()
        if (match := _ERROR.match(line)) and match.group("module") == relative
    )


def price(config: dict[str, object], module: pathlib.Path) -> dict[str, int] | None:
    """Errors the module brings and where the two counters land with it inside."""
    declared = [str(entry) for entry in config["files"]]  # type: ignore[union-attr]
    candidate = module.relative_to(_ROOT).as_posix()
    completed = run_scoped(config, [*declared, candidate])
    if not _VERDICT.search(completed.stdout):
        return None
    scope = declared_scope(config)
    before_crossers, before_reached = crossings(scope)
    after_crossers, after_reached = crossings(scope | {module})
    return {
        "errors": errors_in(completed.stdout, module),
        "crossers": len(after_crossers),
        "reached": len(after_reached),
        "delta_crossers": len(after_crossers) - len(before_crossers),
        "delta_reached": len(after_reached) - len(before_reached),
    }


def outside(config: dict[str, object]) -> list[pathlib.Path]:
    return sorted(set(_PACKAGE.rglob("*.py")) - declared_scope(config))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "module", nargs="*", help="paths under cyberai/; default: the whole outside"
    )
    args = parser.parse_args()
    config = settings()
    if args.module:
        candidates = [(_ROOT / entry).resolve() for entry in args.module]
    else:
        candidates = outside(config)
    scope = declared_scope(config)
    crossers, reached = crossings(scope)
    print(f"scope:   {len(scope)} modules, {len(crossers)} crossers reaching {len(reached)}")
    print(f"{'module':<52} {'errors':>6} {'crossers':>9} {'reached':>8}")
    for module in candidates:
        if not module.exists():
            print(f"{module.relative_to(_ROOT).as_posix():<52} {'absent':>6}")
            return 2
        if module in scope:
            print(f"{module.relative_to(_ROOT).as_posix():<52} {'in':>6}")
            continue
        measured = price(config, module)
        if measured is None:
            print(
                "the checker returned no verdict: this environment was not measured",
                file=sys.stderr,
            )
            return 2
        name = module.relative_to(_ROOT).as_posix()
        print(
            f"{name:<52} {measured['errors']:>6} "
            f"{measured['crossers']:>4} {measured['delta_crossers']:>+4} "
            f"{measured['reached']:>4} {measured['delta_reached']:>+4}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
