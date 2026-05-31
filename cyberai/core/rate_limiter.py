"""
Rate limiter for NVD API and other external APIs.
NVD allows 5 req/30s without API key, 50 req/30s with key.
"""

from __future__ import annotations
import time
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class RateLimiterConfig:
    requests_per_window: int = 5
    window_seconds: float = 30.0
    retry_attempts: int = 3
    retry_delay: float = 6.0
    backoff_factor: float = 2.0


class RateLimiter:
    """
    Token bucket rate limiter — thread safe.
    Tracks request timestamps in a sliding window.
    """

    def __init__(self, config: RateLimiterConfig = None):
        self.config = config or RateLimiterConfig()
        self._lock = threading.Lock()
        self._timestamps: list[float] = []
        self._total_requests = 0
        self._total_waits = 0
        self._total_wait_time = 0.0

    def acquire(self) -> float:
        """
        Block until a request slot is available.
        Returns wait time in seconds.
        """
        with self._lock:
            waited = self._wait_if_needed()
            self._timestamps.append(time.monotonic())
            self._total_requests += 1
            return waited

    def _wait_if_needed(self) -> float:
        now = time.monotonic()
        window = self.config.window_seconds
        max_req = self.config.requests_per_window

        # Remove timestamps outside the window
        self._timestamps = [t for t in self._timestamps if now - t < window]

        if len(self._timestamps) < max_req:
            return 0.0

        # Must wait until oldest timestamp leaves the window
        oldest = self._timestamps[0]
        wait_for = window - (now - oldest) + 0.05  # small buffer

        if wait_for > 0:
            self._total_waits += 1
            self._total_wait_time += wait_for
            time.sleep(wait_for)

        # Re-clean after sleep
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < window]
        return wait_for

    def stats(self) -> dict:
        return {
            "total_requests": self._total_requests,
            "total_waits": self._total_waits,
            "total_wait_time_s": round(self._total_wait_time, 2),
            "config": {
                "requests_per_window": self.config.requests_per_window,
                "window_seconds": self.config.window_seconds,
            },
        }


# ── pre-built configs ─────────────────────────────────────────────────

NVD_RATE_LIMITER_NO_KEY = RateLimiter(
    RateLimiterConfig(
        requests_per_window=5,
        window_seconds=30.0,
        retry_attempts=3,
        retry_delay=6.0,
    )
)

NVD_RATE_LIMITER_WITH_KEY = RateLimiter(
    RateLimiterConfig(
        requests_per_window=50,
        window_seconds=30.0,
        retry_attempts=3,
        retry_delay=1.0,
    )
)


def get_nvd_limiter(api_key: Optional[str] = None) -> RateLimiter:
    """Return appropriate NVD rate limiter based on key presence."""
    if api_key:
        return NVD_RATE_LIMITER_WITH_KEY
    return NVD_RATE_LIMITER_NO_KEY


# ── per-API limiters ──────────────────────────────────────────────────
# Conservative defaults; tune per environment if needed.

EPSS_RATE_LIMITER = RateLimiter(
    RateLimiterConfig(
        requests_per_window=10,
        window_seconds=1.0,
    )
)
OPENAI_RATE_LIMITER = RateLimiter(
    RateLimiterConfig(
        requests_per_window=20,
        window_seconds=1.0,
    )
)
ANTHROPIC_RATE_LIMITER = RateLimiter(
    RateLimiterConfig(
        requests_per_window=10,
        window_seconds=1.0,
    )
)
PHANTOM_GRID_RATE_LIMITER = RateLimiter(
    RateLimiterConfig(
        requests_per_window=30,
        window_seconds=1.0,
    )
)

LIMITERS = {
    "nvd_no_key": NVD_RATE_LIMITER_NO_KEY,
    "nvd_with_key": NVD_RATE_LIMITER_WITH_KEY,
    "epss": EPSS_RATE_LIMITER,
    "openai": OPENAI_RATE_LIMITER,
    "anthropic": ANTHROPIC_RATE_LIMITER,
    "phantom_grid": PHANTOM_GRID_RATE_LIMITER,
}


def get_limiter(name: str) -> RateLimiter:
    """Fetch a named per-API limiter."""
    if name not in LIMITERS:
        raise KeyError(f"Unknown rate limiter: {name!r}")
    return LIMITERS[name]
