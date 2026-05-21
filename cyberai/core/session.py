"""
DEPRECATED: backward-compatibility shim.

All session-related models now live in cyberai.core.scan_session.
This module re-exports them so existing imports keep working:

    from cyberai.core.session import PentestSession, Severity, Finding

…still works, but new code should use:

    from cyberai.core.scan_session import ScanSession, Severity, Finding

PentestSession is now an alias for ScanSession.
SessionState is a compatibility enum that mirrors ScanState plus an
IDLE alias (legacy name for the initial state).

This shim will be removed once all import sites are migrated (planned
for day 7 of the STANDOFF rewrite).
"""
from __future__ import annotations

import warnings
from enum import Enum

# Re-export everything from the new home
from cyberai.core.scan_session import (
    Finding,
    PhaseResult,
    ScanPhase,
    ScanSession,
    ScanState,
    Severity,
)


# ── compatibility enum ────────────────────────────────────────────────


class SessionState(str, Enum):
    """
    Legacy enum. Mirrors ScanState values exactly so equality checks
    against ScanState still work (both are str-enums), plus exposes
    IDLE as an alias for the initial state.

    >>> SessionState.IDLE == ScanState.CREATED       # str-equal
    True
    >>> SessionState.RECON.value == ScanState.RECON.value
    True
    """
    # IDLE was the old name for the initial state; CREATED is the new name.
    # We keep IDLE present and equal to "created" so old tests pass.
    IDLE      = "created"
    CREATED   = "created"
    RUNNING   = "running"
    RECON     = "recon"
    INTEL     = "intel"
    EXPLOIT   = "exploit"
    REPORT    = "report"
    REPORTING = "report"   # legacy alias of REPORT
    COMPLETED = "completed"
    COMPLETE  = "completed"  # legacy alias of COMPLETED
    FAILED    = "failed"
    CANCELLED = "cancelled"


# ── compatibility session class ───────────────────────────────────────


class PentestSession(ScanSession):
    """
    Legacy alias for ScanSession.

    Differences from plain ScanSession (all for backward compat):

    * Initial state is exposed as `state == SessionState.IDLE`
      (the underlying value is "created" so equality holds).
    * Provides `recon_data` / `intel_data` / `exploit_data` dict
      attributes that some old tests and modules still write to.
    * Provides `set_state()` as an alias for the new `set_phase()`,
      accepting both SessionState and ScanState values.
    """

    def __init__(self, target: str = "", **kwargs: object) -> None:
        super().__init__(target=target, **kwargs)
        self.recon_data:   dict = {}
        self.intel_data:   dict = {}
        self.exploit_data: dict = {}

    # Legacy method name used by older tests
    def set_state(self, state: "SessionState | ScanState | str") -> None:
        """Set the session state. Accepts SessionState, ScanState, or raw str."""
        if isinstance(state, Enum):
            value = state.value
        else:
            value = str(state)
        # ScanState accepts the string value because both are str-enums
        self.state = ScanState(value)


__all__ = [
    "Finding",
    "PentestSession",
    "PhaseResult",
    "ScanPhase",
    "ScanSession",
    "ScanState",
    "SessionState",
    "Severity",
]


def _emit_deprecation_once() -> None:
    """Emit deprecation warning at import time, once per process."""
    warnings.warn(
        "cyberai.core.session is deprecated; "
        "import from cyberai.core.scan_session instead. "
        "This shim will be removed in day 7 of the STANDOFF rewrite.",
        DeprecationWarning,
        stacklevel=2,
    )


_emit_deprecation_once()
