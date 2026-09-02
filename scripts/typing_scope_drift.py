#!/usr/bin/env python3
"""Report modules that pass `mypy --strict` while sitting outside the scope.

`[tool.mypy] files` names five directories and seventy-two individual modules.
A directory keeps its guarantee open: a module added inside one is checked from
the moment it lands. A named module does not. A sibling dropped next to one of
the seventy-two passes strictly, is never checked, and nothing says so. The
declared scope then understates what the repository holds, and it understates
it more with every module added.

This runs the checker over the whole package, subtracts the resolved scope from
the modules that reported nothing, and fails when anything is left. What is
left is not a defect in the module; it is a module that could be declared and
is not.

The flags come from `[tool.mypy]` rather than from literals here, so the wide
run and the scoped run differ in scope and in nothing else. The cache is
deliberately separate: a run that reuses a cache left by a run of another shape
re-emits errors for modules it did not check, and the job runs `mypy`
immediately before this one.
"""

from __future__ import annotations

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


def _settings() -> dict[str, object]:
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["tool"]["mypy"]


def _declared_scope(settings: dict[str, object]) -> set[pathlib.Path]:
    resolved: set[pathlib.Path] = set()
    for entry in settings["files"]:
        path = _ROOT / str(entry)
        resolved.update(path.rglob("*.py")) if path.is_dir() else resolved.add(path)
    return resolved


def _wide_run(settings: dict[str, object], cache: pathlib.Path) -> str:
    command = [sys.executable, "-m", "mypy", "--cache-dir", str(cache)]
    if settings.get("strict"):
        command.append("--strict")
    if settings.get("ignore_missing_imports"):
        command.append("--ignore-missing-imports")
    if "python_version" in settings:
        command += ["--python-version", str(settings["python_version"])]
    command.append(_PACKAGE.relative_to(_ROOT).as_posix())
    return subprocess.run(command, cwd=_ROOT, capture_output=True, text=True, check=False).stdout


def _modules_with_errors(output: str) -> set[pathlib.Path]:
    found: set[pathlib.Path] = set()
    for line in output.splitlines():
        match = _ERROR.match(line)
        if match:
            found.add(_ROOT / match.group("module"))
    return found


def main() -> int:
    settings = _settings()
    with tempfile.TemporaryDirectory() as cache:
        output = _wide_run(settings, pathlib.Path(cache))
    package = set(_PACKAGE.rglob("*.py"))
    failing = _modules_with_errors(output) & package
    scope = _declared_scope(settings)
    clean = package - failing

    print(f"package: {len(package)} modules")
    print(f"scope:   {len(scope)} modules declared in [tool.mypy] files")
    print(f"clean:   {len(clean)} modules report nothing under the same flags")
    print(f"errors:  {sum(1 for line in output.splitlines() if _ERROR.match(line))}")

    drift = sorted(path.relative_to(_ROOT).as_posix() for path in clean - scope)
    if not drift:
        print("drift:   none")
        return 0
    print(f"drift:   {len(drift)} clean modules are not declared")
    for path in drift:
        print(f"  {path}")
    print("Declare them in [tool.mypy] files, or say on the scope page why they stay out.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
