"""Some failures end a phase; two end the run.

T4 in STANDOFF-KEY asked for the bare `except Exception` in the orchestrator
to be replaced with typed handling of network, LLM and tool errors. Measured
against the code, that item is the wrong fix. The clause wraps `_dispatch`,
which reaches nmap, httpx, subprocesses, three LLM providers and several
external binaries; no honest list of what they raise can be written, and a
narrower clause would trade a failed phase for a failed run. The docstring
that calls it deliberate is right.

The real defect was the opposite one, and it was found by running it rather
than by reading. `BudgetExceeded` and `EgressViolation` were caught here too.
A run whose spending cap was crossed recorded a failed phase and moved to the
next one, free to spend again -- the cap stopped being a cap exactly when it
began to matter. A run whose air-gapped path was asked to reach a remote
provider carried on after the property it exists for had already been broken.

Both are now re-raised, with the phase still recorded as failed so the
session says where the run ended. Everything else is still caught, which is
what the last test here pins: this change must not turn a dead target into a
dead run.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from cyberai.core.config import CyberAIConfig
from cyberai.core.cost_tracker import BudgetExceeded
from cyberai.core.egress_guard import EgressViolation
from cyberai.core.orchestrator import AsyncOrchestrator, Orchestrator
from cyberai.core.scan_session import ScanPhase, ScanSession


def _run_two_phases(exc: BaseException) -> tuple[ScanSession, BaseException | None]:
    """Drive two phases through _run_phase with the same failure on each."""
    orch = Orchestrator(CyberAIConfig())
    session = ScanSession(target="t.local")
    escaped: BaseException | None = None
    try:
        with patch.object(Orchestrator, "_dispatch", side_effect=exc):
            orch._run_phase(session, ScanPhase.RECON)
            orch._run_phase(session, ScanPhase.INTEL)
    except BaseException as caught:  # noqa: BLE001 -- the point of the test
        escaped = caught
    return session, escaped


def test_a_crossed_budget_stops_the_run() -> None:
    session, escaped = _run_two_phases(BudgetExceeded(1.5, 1.0))
    assert isinstance(escaped, BudgetExceeded)
    # One phase, not two: the second never got the chance to spend again.
    assert len(session.phases) == 1
    assert session.phases[0].success is False


def test_an_egress_violation_stops_the_run() -> None:
    session, escaped = _run_two_phases(EgressViolation("provider is not local"))
    assert isinstance(escaped, EgressViolation)
    assert len(session.phases) == 1
    assert session.phases[0].success is False


def test_the_phase_is_recorded_before_the_exception_leaves() -> None:
    """A run that ends must still say where it ended."""
    session, _ = _run_two_phases(BudgetExceeded(2.0, 1.0))
    assert session.phases[0].phase is ScanPhase.RECON
    assert "budget exceeded" in (session.phases[0].error or "")


def test_an_ordinary_failure_still_only_ends_its_phase() -> None:
    """The guarantee this change must not break."""
    session, escaped = _run_two_phases(ConnectionError("refused"))
    assert escaped is None
    assert len(session.phases) == 2
    assert not any(p.success for p in session.phases)


def _run_two_phases_async(exc: BaseException) -> tuple[ScanSession, BaseException | None]:
    """The same drive through AsyncOrchestrator.

    _run_phase_async is a separate method on a separate class carrying its own
    copy of the clause. Testing only the synchronous one would leave the copy
    free to drift back, and a run driven through the async entry point is the
    same run under the same spending cap.
    """
    orch = AsyncOrchestrator(config=CyberAIConfig(), dry_run=False)
    session = ScanSession(target="t.local")
    escaped: BaseException | None = None

    async def drive() -> None:
        await orch._run_phase_async(session, ScanPhase.RECON)
        await orch._run_phase_async(session, ScanPhase.INTEL)

    with patch.object(orch, "_dispatch_async", new_callable=AsyncMock, side_effect=exc):
        try:
            asyncio.run(drive())
        except BaseException as caught:  # noqa: BLE001 -- the point of the test
            escaped = caught
    return session, escaped


def test_the_async_path_stops_on_a_crossed_budget_too() -> None:
    session, escaped = _run_two_phases_async(BudgetExceeded(1.5, 1.0))
    assert isinstance(escaped, BudgetExceeded)
    assert len(session.phases) == 1
    assert session.phases[0].success is False


def test_the_async_path_still_survives_an_ordinary_failure() -> None:
    session, escaped = _run_two_phases_async(ConnectionError("refused"))
    assert escaped is None
    assert len(session.phases) == 2
    assert not any(p.success for p in session.phases)


@pytest.mark.parametrize(
    "exc",
    [ConnectionError("refused"), BudgetExceeded(1.5, 1.0)],
    ids=["ordinary", "fatal"],
)
def test_the_recorded_error_names_its_type(exc: BaseException) -> None:
    """ "refused" alone does not say whether a target or a defect produced it."""
    session, _ = _run_two_phases(exc)
    assert (session.phases[0].error or "").startswith(f"{type(exc).__name__}: ")
