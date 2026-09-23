"""The price reported before a module is added must be the price the guard charges.

Two files count the same crossing. test_typing_scope_boundary_is_declared holds
the numbers the scope page states; scripts/scope_price.py projects where those
numbers land when a candidate module moves inside. Two counters over one import
graph agree today because one was written from the other, and nothing keeps
them agreeing: the day one follows relative imports differently, the price read
before the change and the price charged after it diverge, and the second is the
one that reds. So the agreement is asserted here rather than assumed.

The projection is asserted through a module already inside the scope. Adding
one changes nothing -- it crosses no edge it did not cross before, and it is
reached by nobody it did not already belong to -- so both counters must hold
still. A pricer that stopped asking whether a target sits outside the scope
would report the whole import graph as crossings and move them.

The refusal is asserted the same way the drift report's is: a run that emits no
verdict line is not a module that costs nothing. An environment without the
checker writes nothing to standard output, and a price taken from that silence
reads as zero errors on a module nobody read.

The script is loaded by path. scripts/ resolves today only because of how the
package is installed, and a gate resting on the install mode is a gate about
one machine.
"""

import importlib.util
import pathlib
import subprocess
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "scope_price.py"
_GUARD = pathlib.Path(__file__).with_name("test_typing_scope_boundary_is_declared.py")


def _by_path(name: str, path: pathlib.Path) -> types.ModuleType:
    """Load by location, never by import root.

    The sibling guard is a test module, and importing it as tests.architecture
    asks the suite to be a package on sys.path. It is not one: the manifest
    gate reads that import as a third-party dependency named tests, and the
    dependency it would really name is the install mode.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"no module at {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pricer() -> types.ModuleType:
    return _by_path("scope_price", _SCRIPT)


def test_the_pricer_counts_the_edge_the_boundary_guard_counts() -> None:
    """One import graph, two readers, one pair of numbers."""
    guard = _by_path("boundary_guard", _GUARD)
    module = _pricer()
    crossers, reached = module.crossings(module.declared_scope(module.settings()))
    assert len(crossers) == guard._EXPECTED_CROSSERS
    assert len(reached) == guard._EXPECTED_REACHED


def test_a_module_already_inside_the_scope_costs_no_movement() -> None:
    """The projection must ask which side of the edge a target sits on."""
    module = _pricer()
    scope = module.declared_scope(module.settings())
    inside = _ROOT / "cyberai" / "agents" / "exploit" / "safety_validator.py"
    assert inside in scope, "the module this test reasons about left the scope"
    before = module.crossings(scope)
    after = module.crossings(scope | {inside})
    assert (len(after[0]), len(after[1])) == (len(before[0]), len(before[1]))


def test_a_run_without_a_verdict_is_not_a_module_that_costs_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Silence from an absent checker must not be read as an empty error list."""
    module = _pricer()
    absent = subprocess.CompletedProcess(["mypy"], 1, stdout="", stderr="No module named mypy")
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: absent)
    priced = module.price(module.settings(), _ROOT / "cyberai" / "core" / "cache.py")
    assert priced is None


def test_a_verdict_with_no_error_lines_prices_a_module_at_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal above must not swallow the honest clean run as well."""
    module = _pricer()
    clean = subprocess.CompletedProcess(
        ["mypy"], 0, stdout="Success: no issues found in 105 source files\n", stderr=""
    )
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: clean)
    priced = module.price(module.settings(), _ROOT / "cyberai" / "core" / "cache.py")
    assert priced is not None
    assert priced["errors"] == 0


def test_the_count_belongs_to_the_module_it_is_charged_to() -> None:
    """Two mutants survived the fakes above: neither fake emits an error line.

    A pricer that counted every error line in the run, or matched any annotated
    line rather than an error, would charge a candidate for the whole package
    and for its notes as well. The output is read here as text, so the parsing
    is asserted without paying for a run.
    """
    module = _pricer()
    output = "\n".join(
        [
            "cyberai/core/cache.py:62: error: Missing type parameters [type-arg]",
            "cyberai/core/cache.py:70: error: Returning Any [no-any-return]",
            "cyberai/core/cache.py:71: note: Consider annotating it",
            "cyberai/core/logger.py:14: error: Missing type parameters [type-arg]",
            "Found 3 errors in 2 files (checked 105 source files)",
        ]
    )
    assert module.errors_in(output, _ROOT / "cyberai" / "core" / "cache.py") == 2
    assert module.errors_in(output, _ROOT / "cyberai" / "core" / "logger.py") == 1
