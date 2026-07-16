"""Behavioral fingerprinting of a target.

Profiles response timing and shape across a series of probes to spot honeypots,
WAFs, and tarpits without valid credentials, and derives a trust score that
downstream phases can use to modulate aggressiveness. Probes are supplied by a
callable so the profiler stays deterministic and network-free under test.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Tuple


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
