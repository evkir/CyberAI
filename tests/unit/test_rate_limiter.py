import pytest
import time
from cyberai.core.rate_limiter import (
    RateLimiter,
    RateLimiterConfig,
    get_nvd_limiter,
)


def test_acquire_no_wait():
    limiter = RateLimiter(
        RateLimiterConfig(
            requests_per_window=10,
            window_seconds=30.0,
        )
    )
    wait = limiter.acquire()
    assert wait == 0.0


def test_stats_tracks_requests():
    limiter = RateLimiter(
        RateLimiterConfig(
            requests_per_window=10,
            window_seconds=30.0,
        )
    )
    limiter.acquire()
    limiter.acquire()
    limiter.acquire()
    assert limiter.stats()["total_requests"] == 3


def test_rate_limit_enforced():
    limiter = RateLimiter(
        RateLimiterConfig(
            requests_per_window=3,
            window_seconds=1.0,
        )
    )
    for _ in range(3):
        limiter.acquire()
    start = time.monotonic()
    limiter.acquire()  # 4th — должен подождать
    elapsed = time.monotonic() - start
    assert elapsed >= 0.5


def test_get_nvd_limiter_no_key():
    limiter = get_nvd_limiter(api_key=None)
    assert limiter.config.requests_per_window == 5


def test_get_nvd_limiter_with_key():
    limiter = get_nvd_limiter(api_key="my-secret-key")
    assert limiter.config.requests_per_window == 50


def test_stats_structure():
    limiter = RateLimiter()
    stats = limiter.stats()
    assert "total_requests" in stats
    assert "total_waits" in stats
    assert "total_wait_time_s" in stats
    assert "config" in stats
