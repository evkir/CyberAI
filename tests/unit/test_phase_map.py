"""PHASE_TOOLS must describe the pipeline that exists, not the one that did.

Nothing in the product reads this table, so a module can be deleted or a
phase can grow new tools and the description keeps naming the old design.
That is what happened while it still backed a --dry-run printer: the exploit
row named two modules that had been deleted months earlier, and the intel row
named two its agent never imported. The printer is gone; the table is not,
because a wrong description of the pipeline is worse than none.

Scope of the guarantee: these tests check that every named module exists and
that every phase the orchestrator runs by default has a row. They do NOT
check that the phase's agent actually imports the module -- agents reach
their tools through deferred imports, package re-exports, and in one case
through the orchestrator itself, so an import-graph assertion would fail on
legitimate code more often than it would catch a stale name.
"""

from __future__ import annotations

import importlib

import pytest

from cyberai.core.orchestrator import Orchestrator
from cyberai.core.phase_map import PHASE_TOOLS
from cyberai.core.scan_session import ScanPhase

ALL_MODULES = [(phase, mod) for phase, (_, mods) in PHASE_TOOLS.items() for mod in mods]


@pytest.mark.parametrize("phase,module", ALL_MODULES, ids=[m for _, m in ALL_MODULES])
def test_named_module_exists(phase: str, module: str) -> None:
    importlib.import_module(module)


def test_every_default_phase_has_a_row() -> None:
    defaults = {p.value for p in Orchestrator.DEFAULT_PHASES}
    assert defaults <= set(PHASE_TOOLS), defaults - set(PHASE_TOOLS)


def test_every_row_is_a_real_phase() -> None:
    known = {p.value for p in ScanPhase}
    assert set(PHASE_TOOLS) <= known, set(PHASE_TOOLS) - known


def test_rows_are_not_empty() -> None:
    for phase, (agent, mods) in PHASE_TOOLS.items():
        assert agent, phase
        assert mods, phase
