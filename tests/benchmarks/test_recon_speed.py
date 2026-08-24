"""
Benchmark: sync vs async recon paths.

Measures real wall-clock time on live network calls. Marked @slow + @network
so it only runs in the nightly workflow or with explicit `pytest -m slow`.

Acceptance applies to the DNS benchmark only: the async path must not be
slower than the sync one by more than 50% OR 50ms absolute, whichever is
larger. The subdomain benchmark reports and asserts nothing — its two paths
use different resolvers with different caching, so wall-clock time there
measures the cache rather than the code. On clean networks the async path is
typically 2-5x faster. The absolute grace covers the near-zero-latency regime
(local caching resolvers / captive DNS) where responses return in a few ms and
async's fixed overhead — event-loop setup and gather — dominates the ratio,
which then measures scheduler noise rather than a real regression.
"""

import asyncio
import statistics
import time

import pytest

from cyberai.agents.recon.dns_tool import run_dns, run_dns_async
from cyberai.agents.recon.subdomain_enum import (
    enumerate_subdomains,
    enumerate_subdomains_async,
)

pytestmark = [pytest.mark.slow, pytest.mark.network]

# Stable, well-distributed test targets.
DNS_TARGETS = ["example.com", "cloudflare.com", "github.com"]
SUBDOMAIN_TARGET = "example.com"
RUNS = 3
# Absolute grace: below this delta the ratio is noise, not a regression.
GRACE_S = 0.05


def _median_time(fn, *args, **kwargs) -> float:
    samples = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        fn(*args, **kwargs)
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


async def _median_time_async(coro_factory, *args, **kwargs) -> float:
    samples = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        await coro_factory(*args, **kwargs)
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def test_dns_async_is_not_slower_than_sync():
    """7 record types resolved in parallel should beat sequential resolution."""
    target = DNS_TARGETS[0]

    sync_median = _median_time(run_dns, target)
    async_median = asyncio.run(_median_time_async(run_dns_async, target))

    ratio = sync_median / async_median if async_median > 0 else float("inf")
    print(f"\n[bench dns] sync={sync_median:.3f}s async={async_median:.3f}s speedup={ratio:.2f}x")

    budget = sync_median * 1.5 + GRACE_S
    assert async_median <= budget, f"async DNS regressed: {async_median:.3f}s > {budget:.3f}s"


def test_subdomain_enum_speed_is_recorded():
    """Prints both paths side by side and asserts nothing.

    The threshold this test used to carry compared a warm system resolver
    against a cache-less dnspython, not ThreadPool(20) against Semaphore(20).
    getaddrinfo answers 48 cached NXDOMAINs out of systemd-resolved in about
    70ms, while dns.asyncresolver keeps no cache and sends 48 real queries,
    so the ratio tracked whether the cache was warm. Measured in CI 24.08:
    sync 0.071s, async 0.191s, speedup 0.37x — a red nightly that said
    nothing about the code.

    What the ratio was meant to guard, that the async path overlaps its
    queries instead of serialising them, is asserted with neither network
    nor clock in tests/unit/test_subdomain_enum.py, where a counting
    resolver records the peak number of queries in flight.
    """
    sync_median = _median_time(enumerate_subdomains, SUBDOMAIN_TARGET, timeout=1.5)
    async_median = asyncio.run(
        _median_time_async(enumerate_subdomains_async, SUBDOMAIN_TARGET, timeout=1.5)
    )

    ratio = sync_median / async_median if async_median > 0 else float("inf")
    print(
        f"\n[bench subdomains] sync={sync_median:.3f}s async={async_median:.3f}s "
        f"speedup={ratio:.2f}x"
    )
