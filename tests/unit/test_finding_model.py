"""Tests for Finding dataclass and ScanSession.add_finding() — KI-5 fix."""

from __future__ import annotations

from cyberai.core.scan_session import Finding, ScanSession, Severity


def test_finding_accepts_target_and_evidence():
    f = Finding(
        id=1,
        severity=Severity.HIGH,
        title="t",
        description="d",
        timestamp="2026-05-21T00:00:00+00:00",
        agent="recon",
        target="10.0.0.1",
        evidence=["nmap line"],
    )
    assert f.target == "10.0.0.1"
    assert f.evidence == ["nmap line"]


def test_finding_cve_and_cve_ids_sync_from_single():
    f = Finding(
        id=1,
        severity=Severity.HIGH,
        title="t",
        description="d",
        timestamp="2026-05-21T00:00:00+00:00",
        agent="intel",
        cve="CVE-2024-1234",
    )
    assert f.cve_ids == ["CVE-2024-1234"]


def test_finding_cve_and_cve_ids_sync_from_list():
    f = Finding(
        id=1,
        severity=Severity.HIGH,
        title="t",
        description="d",
        timestamp="2026-05-21T00:00:00+00:00",
        agent="intel",
        cve_ids=["CVE-2024-1234", "CVE-2024-5678"],
    )
    assert f.cve == "CVE-2024-1234"


def test_finding_defaults_not_shared():
    f1 = Finding(
        id=1,
        severity=Severity.LOW,
        title="a",
        description="d",
        timestamp="2026-05-21T00:00:00+00:00",
        agent="x",
    )
    f2 = Finding(
        id=2,
        severity=Severity.LOW,
        title="b",
        description="d",
        timestamp="2026-05-21T00:00:00+00:00",
        agent="x",
    )
    f1.evidence.append("only f1")
    assert f2.evidence == []


def test_session_add_finding_basic():
    s = ScanSession(target="example.com")
    f = s.add_finding(Severity.MEDIUM, "Open SSH", "Port 22", "recon")
    assert f.id == 1
    assert f.target == "example.com"


def test_session_add_finding_explicit_target():
    s = ScanSession(target="parent")
    f = s.add_finding(Severity.HIGH, "t", "d", "a", target="sub.example.com")
    assert f.target == "sub.example.com"


def test_session_findings_get_sequential_ids():
    s = ScanSession(target="x")
    for i in range(3):
        s.add_finding(Severity.INFO, f"t{i}", "d", "a")
    assert [f.id for f in s.findings] == [1, 2, 3]


def test_session_summary_severity_breakdown():
    s = ScanSession(target="x")
    s.add_finding(Severity.CRITICAL, "c", "d", "a")
    s.add_finding(Severity.HIGH, "h1", "d", "a")
    s.add_finding(Severity.HIGH, "h2", "d", "a")
    summary = s.summary()
    assert summary["findings_total"] == 3
    assert summary["severity_breakdown"]["CRITICAL"] == 1
    assert summary["severity_breakdown"]["HIGH"] == 2
