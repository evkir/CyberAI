"""Backward-compat shim tests for cyberai.core.session — day 3 of STANDOFF."""

from __future__ import annotations

import warnings


def test_legacy_imports_still_work():
    from cyberai.core.session import (
        Finding,  # noqa: F401 — shim must re-export this legacy name
        PentestSession,  # noqa: F401 — shim must re-export this legacy name
        Severity,
        SessionState,
    )

    assert Severity.CRITICAL == "CRITICAL"
    assert SessionState.IDLE.value == "created"


def test_pentestsession_is_a_scansession():
    from cyberai.core.scan_session import ScanSession
    from cyberai.core.session import PentestSession

    assert isinstance(PentestSession(target="x"), ScanSession)


def test_pentestsession_keeps_legacy_data_attrs():
    from cyberai.core.session import PentestSession

    s = PentestSession(target="x")
    s.recon_data["nmap"] = {"ports": [80]}
    s.intel_data["cves"] = []
    s.exploit_data["chains"] = []
    assert s.recon_data["nmap"] == {"ports": [80]}


def test_pentestsession_add_finding_works():
    from cyberai.core.session import PentestSession, Severity

    s = PentestSession(target="x")
    f = s.add_finding(Severity.HIGH, "t", "d", "recon")
    assert f.id == 1


def test_pentestsession_set_state_legacy_method():
    from cyberai.core.session import PentestSession, SessionState

    s = PentestSession(target="x")
    assert s.state == SessionState.IDLE
    s.set_state(SessionState.RECON)
    assert s.state.value == "recon"


def test_session_module_emits_deprecation_warning():
    import importlib
    import cyberai.core.session as legacy

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        importlib.reload(legacy)
        assert any(
            issubclass(x.category, DeprecationWarning) and "scan_session" in str(x.message)
            for x in w
        )
