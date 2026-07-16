"""Behavioral fingerprinting of a target.

Profiles response timing and shape across a series of probes to spot honeypots,
WAFs, and tarpits without valid credentials, and derives a trust score that
downstream phases can use to modulate aggressiveness. Probes are supplied by a
callable so the profiler stays deterministic and network-free under test.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class ProbeResult:
    """A single probe observation."""

    latency: float  # seconds
    status: int = 0
    length: int = 0
    banner: str = ""
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ResponseProfile:
    """Aggregated timing/shape statistics over a series of probes."""

    results: List[ProbeResult]

    @property
    def latencies(self) -> List[float]:
        return [r.latency for r in self.results]

    @property
    def mean_latency(self) -> float:
        lat = self.latencies
        return statistics.fmean(lat) if lat else 0.0

    @property
    def stdev(self) -> float:
        lat = self.latencies
        return statistics.pstdev(lat) if len(lat) > 1 else 0.0

    @property
    def jitter(self) -> float:
        """Coefficient of variation of latency (0.0 = perfectly uniform)."""
        mean = self.mean_latency
        return self.stdev / mean if mean > 0 else 0.0

    @property
    def shapes(self) -> List[Tuple[int, int]]:
        return [(r.status, r.length) for r in self.results]

    @property
    def uniform_shape(self) -> bool:
        """True when every probe returned an identical (status, length) shape."""
        shapes = self.shapes
        return len(set(shapes)) == 1 if shapes else False


def profile_responses(probe_fn: Callable[[int], ProbeResult], n: int = 5) -> ResponseProfile:
    """Run ``probe_fn(i)`` ``n`` times and aggregate the observations."""
    results = [probe_fn(i) for i in range(max(1, n))]
    return ResponseProfile(results=results)


# Canonical WAF header/cookie signatures (name, value-substring; "" = presence only).
_WAF_SIGNATURES: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "cloudflare": (("server", "cloudflare"), ("cf-ray", ""), ("set-cookie", "__cf_bm")),
    "akamai": (("server", "akamaighost"), ("x-akamai-transformed", ""), ("set-cookie", "_abck")),
    "modsecurity": (("server", "mod_security"), ("server", "noyb"), ("server", "nyob")),
    "aws": (("x-powered-by", "aws waf"), ("x-amzn-waf-action", "")),
    "sucuri": (("x-sucuri-id", ""), ("server", "sucuri")),
    "f5-bigip": (("set-cookie", "bigipserver"),),
    "fortiweb": (("set-cookie", "fortiwafsid"),),
}

# Default SSH banners shipped by common honeypots (lowercased).
_HONEYPOT_BANNERS: Dict[str, Tuple[str, ...]] = {
    "cowrie": ("ssh-2.0-openssh_6.0p1 debian-4+deb7u2",),
    "kippo": ("ssh-2.0-openssh_5.1p1 debian-5",),
}

_TARPIT_LATENCY_SECONDS = 2.0


def detect_waf(headers: Dict[str, str]) -> List[str]:
    """Return WAF signals from response headers (canonical wafw00f-style tells)."""
    lowered = {k.lower(): str(v).lower() for k, v in headers.items()}
    signals: List[str] = []
    for vendor, sigs in _WAF_SIGNATURES.items():
        for name, marker in sigs:
            if name in lowered and (marker == "" or marker in lowered[name]):
                signals.append(f"waf:{vendor}")
                break
    return signals


def detect_honeypot(banners: List[str]) -> List[str]:
    """Return honeypot signals from service banners (default emulated banners)."""
    lowered = [b.lower() for b in banners if b]
    signals: List[str] = []
    for name, defaults in _HONEYPOT_BANNERS.items():
        if any(default in b for b in lowered for default in defaults):
            signals.append(f"honeypot:{name}")
    return signals


def detect_tarpit(profile: ResponseProfile) -> List[str]:
    """Return a tarpit signal when latency is abnormally high (endlessh/LaBrea class)."""
    if profile.mean_latency >= _TARPIT_LATENCY_SECONDS:
        return ["tarpit:high-latency"]
    return []


# Multiplicative trust penalty per signal kind (honeypot most hostile, WAF least).
_SIGNAL_PENALTY: Dict[str, float] = {"honeypot": 0.9, "tarpit": 0.8, "waf": 0.4}
_HOSTILE_TRUST_THRESHOLD = 0.3


def trust_score(signals: List[str]) -> float:
    """Derive a 0.0 (hostile) .. 1.0 (clean) trust score from detected signals."""
    score = 1.0
    for sig in signals:
        kind = sig.split(":", 1)[0]
        score *= 1.0 - _SIGNAL_PENALTY.get(kind, 0.0)
    return round(max(0.0, min(1.0, score)), 3)


@dataclass
class BehavioralResult:
    """Outcome of a behavioral fingerprint pass over a target."""

    target: str
    trust: float
    signals: List[str]
    hostile: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "trust": self.trust,
            "signals": self.signals,
            "hostile": self.hostile,
        }


class BehavioralFingerprint:
    """Profile a target and derive a trust score to modulate aggressiveness."""

    def __init__(self, threshold: float = _HOSTILE_TRUST_THRESHOLD) -> None:
        self.threshold = threshold

    def run(
        self,
        target: str,
        *,
        probe_fn: Callable[[int], ProbeResult],
        headers: Optional[Dict[str, str]] = None,
        banners: Optional[List[str]] = None,
        n: int = 5,
    ) -> BehavioralResult:
        """Collect a profile, detect defenses, and compute the target trust score."""
        profile = profile_responses(probe_fn, n=n)
        signals = (
            detect_waf(headers or {}) + detect_honeypot(banners or []) + detect_tarpit(profile)
        )
        trust = trust_score(signals)
        return BehavioralResult(
            target=target, trust=trust, signals=signals, hostile=trust < self.threshold
        )

    def record(self, result: BehavioralResult, session: Any, agent: str = "recon") -> None:
        """Store the trust result in the KB and raise a finding when defenses are seen."""
        from cyberai.core.scan_session import Severity

        session.kb_set("recon.trust", result.to_dict())
        if not result.signals:
            return
        severity = Severity.MEDIUM if result.hostile else Severity.INFO
        session.add_finding(
            severity=severity,
            title=f"Behavioral fingerprint on {result.target}: {', '.join(result.signals)}",
            description=(
                f"Trust score {result.trust}; "
                f"{'hostile — reduce aggressiveness' if result.hostile else 'defended target'}."
            ),
            agent=agent,
            target=result.target,
            evidence=result.signals,
        )
