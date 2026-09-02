"""Every third-party import needs a typing decision, declared where the
environment is built rather than discovered on whichever machine ran last.

Day 23 bounded the checker and named `types-PyYAML`. It named one stub and
stopped. Measured after that: a workstation carrying `types-networkx` reports
ten `type-arg` errors in `cyberai/core/kb_graph.py` and a runner without it
reports none, because `ignore_missing_imports` turns an unstubbed `networkx`
into `Any` and leaves nothing to complain about. Same source, same checker,
cold cache, opposite verdicts. A scope drawn from measurement cannot rest on a
package that only one machine happens to have.

The decision is recorded here rather than sensed. Nothing below inspects
site-packages: the test job installs the test extra, which carries no stubs at
all, so an assertion phrased over installed stubs would be green where the
type checker runs and red where the tests do. What is inspected is the
declaration in `pyproject.toml` and the `py.typed` marker that ships inside
each runtime dependency, both of which are present in every job.

The rule runs both ways. A module imported without inline types and without an
entry below is an undeclared dependency of the measured scope; an entry for a
module the package never imports is a producer with no consumer.
"""

import ast
import importlib.util
import pathlib
import re
import sys
import tomllib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PACKAGE = _ROOT / "cyberai"
_PYPROJECT = _ROOT / "pyproject.toml"

# Imported modules that ship no `py.typed`, mapped to the distribution that
# supplies their stubs. Every value has to appear in the dev extra.
_STUB_DISTRIBUTION_FOR = {
    "yaml": "types-PyYAML",
    "networkx": "types-networkx",
}

# Imported, installed, no `py.typed`, and typeshed publishes nothing for it.
# `ignore_missing_imports` renders it `Any` on every machine, so unlike an
# optional stub package it cannot move the clean set from one host to another.
_NO_STUBS_PUBLISHED = {"whois"}


def _third_party_imports() -> set[str]:
    found: set[str] = set()
    for module in _PACKAGE.rglob("*.py"):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    return {name for name in found if name not in sys.stdlib_module_names and name != "cyberai"}


def _package_directory(name: str) -> pathlib.Path | None:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return None
    if spec is None or spec.origin is None or spec.origin == "built-in":
        return None
    return pathlib.Path(spec.origin).parent


def _imports_without_inline_types() -> set[str]:
    """Installed third-party imports that carry no `py.typed` of their own.

    An import that resolves to nothing is skipped rather than judged. The
    guarded `from _server import ...` in the bench apps is such an import by
    design, and the checker sees an absent package exactly as it sees an
    unstubbed one.
    """
    without: set[str] = set()
    for name in _third_party_imports():
        directory = _package_directory(name)
        if directory is not None and not (directory / "py.typed").exists():
            without.add(name)
    return without


def _declared_dev_distributions() -> set[str]:
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return {
        re.split(r"[<>=!~]", entry, maxsplit=1)[0]
        for entry in config["project"]["optional-dependencies"]["dev"]
    }


@pytest.mark.architecture
def test_no_untyped_import_is_left_undeclared() -> None:
    accounted = set(_STUB_DISTRIBUTION_FOR) | _NO_STUBS_PUBLISHED
    undeclared = sorted(_imports_without_inline_types() - accounted)
    assert not undeclared, (
        f"{undeclared} ship no py.typed and are named neither as stubbed nor as "
        "unstubbable; whoever installs their stubs measures a different scope"
    )


@pytest.mark.architecture
def test_no_module_is_named_that_the_package_never_imports() -> None:
    imported = _third_party_imports()
    stale = sorted((set(_STUB_DISTRIBUTION_FOR) | _NO_STUBS_PUBLISHED) - imported)
    assert not stale, (
        f"{stale} are named here but imported nowhere in the package; the entry "
        "outlived the import it was written for"
    )


@pytest.mark.architecture
def test_every_stub_the_scope_needs_is_declared_in_the_dev_extra() -> None:
    declared = _declared_dev_distributions()
    missing = sorted(
        {
            distribution
            for module, distribution in _STUB_DISTRIBUTION_FOR.items()
            if module in _imports_without_inline_types() and distribution not in declared
        }
    )
    assert not missing, (
        f"{missing} decide what the checker reports, but the dev extra does not "
        "install them, so a fresh runner measures a narrower scope than a workstation"
    )


@pytest.mark.architecture
def test_the_dev_extra_declares_no_stub_nothing_relies_on() -> None:
    needed = set(_STUB_DISTRIBUTION_FOR.values())
    unused = sorted(
        name
        for name in _declared_dev_distributions()
        if name.lower().startswith("types-") and name not in needed
    )
    assert not unused, f"{unused} are installed for every developer and no import here needs them"
