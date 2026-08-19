"""Tests for behavioral fingerprinting: profiling, detectors, and trust score."""

from __future__ import annotations

from cyberai.agents.recon.behavioral import (
    BehavioralFingerprint,
    BehavioralResult,
    ProbeResult,
    ResponseProfile,
    detect_honeypot,
    detect_tarpit,
    detect_waf,
    profile_responses,
    trust_score,
)
from cyberai.core.scan_session import ScanSession, Severity

# ── profiler ──────────────────────────────────────────────────────────


def test_profile_uniform():
    p = profile_responses(lambda i: ProbeResult(latency=0.1, status=200, length=10), n=4)
    assert p.mean_latency == 0.1
    assert p.stdev == 0.0
    assert p.jitter == 0.0
    assert p.uniform_shape is True


def test_profile_varied():
    p = profile_responses(lambda i: ProbeResult(latency=0.1 + i, status=200 + i, length=i), n=3)
    assert p.stdev > 0.0
    assert p.jitter > 0.0
    assert p.uniform_shape is False


def test_profile_single_probe_and_clamp():
    p = profile_responses(lambda i: ProbeResult(latency=0.2), n=0)  # clamps to 1
    assert len(p.results) == 1
    assert p.stdev == 0.0


def test_profile_empty_results_edge():
    p = ResponseProfile(results=[])
    assert p.mean_latency == 0.0
    assert p.stdev == 0.0
    assert p.jitter == 0.0
    assert p.uniform_shape is False


# ── WAF detection ─────────────────────────────────────────────────────


def test_detect_waf_cloudflare():
    assert detect_waf({"Server": "cloudflare", "CF-RAY": "abc"}) == ["waf:cloudflare"]


def test_detect_waf_akamai_cookie():
    assert detect_waf({"Set-Cookie": "_abck=1; path=/"}) == ["waf:akamai"]


def test_detect_waf_modsecurity_noyb_marker():
    assert detect_waf({"Server": "Apache NOYB"}) == ["waf:modsecurity"]


def test_detect_waf_aws_and_sucuri():
    assert detect_waf({"X-Powered-By": "AWS WAF"}) == ["waf:aws"]
    assert detect_waf({"X-Sucuri-ID": "9"}) == ["waf:sucuri"]


def test_detect_waf_clean():
    assert detect_waf({"Server": "nginx"}) == []


# ── honeypot / tarpit ─────────────────────────────────────────────────


def test_detect_honeypot_cowrie_and_kippo():
    assert detect_honeypot(["SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"]) == ["honeypot:cowrie"]
    assert detect_honeypot(["SSH-2.0-OpenSSH_5.1p1 Debian-5"]) == ["honeypot:kippo"]


def test_detect_honeypot_clean_and_empty():
    assert detect_honeypot(["SSH-2.0-OpenSSH_9.6p1 Ubuntu", ""]) == []


def test_detect_tarpit():
    slow = ResponseProfile([ProbeResult(latency=3.0)])
    fast = ResponseProfile([ProbeResult(latency=0.05)])
    assert detect_tarpit(slow) == ["tarpit:high-latency"]
    assert detect_tarpit(fast) == []


# ── trust score ───────────────────────────────────────────────────────


def test_trust_score_ordering():
    assert trust_score([]) == 1.0
    assert trust_score(["waf:cloudflare"]) == 0.6
    assert trust_score(["tarpit:high-latency"]) == 0.2
    assert trust_score(["honeypot:cowrie"]) == 0.1
    assert trust_score(["honeypot:cowrie"]) < trust_score(["waf:x"]) < trust_score([])


def test_trust_score_unknown_kind_is_neutral():
    assert trust_score(["other:thing"]) == 1.0


# ── BehavioralFingerprint ─────────────────────────────────────────────


def _probe(_i):
    return ProbeResult(latency=0.1)


def test_fingerprint_run_variants():
    bf = BehavioralFingerprint()
    honeypot = bf.run("h", probe_fn=_probe, banners=["SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"])
    waf = bf.run("w", probe_fn=_probe, headers={"Server": "cloudflare", "CF-RAY": "x"})
    clean = bf.run("c", probe_fn=_probe)
    assert honeypot.hostile is True and honeypot.trust == 0.1
    assert waf.hostile is False and waf.trust == 0.6
    assert clean.trust == 1.0 and clean.signals == []
    assert honeypot.to_dict()["signals"] == ["honeypot:cowrie"]


def test_fingerprint_record_hostile_and_clean():
    bf = BehavioralFingerprint()
    s = ScanSession(target="h")
    hostile = BehavioralResult("h", 0.1, ["honeypot:cowrie"], hostile=True)
    bf.record(hostile, s)
    assert s.kb.get("recon.trust")["hostile"] is True
    assert len(s.findings) == 1 and s.findings[0].severity == Severity.MEDIUM

    s2 = ScanSession(target="c")
    bf.record(BehavioralResult("c", 1.0, [], hostile=False), s2)
    assert s2.kb.get("recon.trust") is not None
    assert len(s2.findings) == 0  # no signals -> no finding


def test_fingerprint_record_defended_info_severity():
    bf = BehavioralFingerprint()
    s = ScanSession(target="w")
    bf.record(BehavioralResult("w", 0.6, ["waf:cloudflare"], hostile=False), s)
    assert s.findings[0].severity == Severity.INFO
