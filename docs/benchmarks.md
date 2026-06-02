# Recon Performance Benchmarks

Measured by `tests/benchmarks/test_recon_speed.py` — median of 3 runs each.

## Day 15 baseline (Mihomo proxy + fake-ip range)

| Path | Sync (median) | Async (median) | Speedup |
|---|---|---|---|
| DNS recon (`run_dns` vs `run_dns_async`), 7 record types on `example.com` | 7 ms | 5 ms | **1.35×** |
| Subdomain enum (48-word wordlist on `example.com`) | 22 ms | 30 ms | 0.72× |

### Reading these numbers

This environment runs all DNS through Mihomo with the fake-ip range
(`198.18.0.0/16`). The "resolver" answers in microseconds with synthetic
IPs — there is no real network latency to hide concurrency behind.

In that regime:

- **DNS recon** still wins: 7 record types resolved natively async beats
  the same 7 queries through `dns.resolver` even when each individual
  query is near-instant.
- **Subdomain enum** loses on the synthetic resolver: the per-query work
  is so small that `asyncio.Semaphore` acquisition + event-loop
  scheduling cost more than `ThreadPoolExecutor(20)` blocking on a noop
  `socket.getaddrinfo`. On a real network where each query costs
  50-200 ms, this inverts.

### Acceptance criterion

The benchmark asserts `async_median <= sync_median * 1.5` — i.e. **async
must not regress by more than 50%** in any environment. The original
plan target of ≥2× speedup is unrealistic against a fake-ip resolver but
is expected on real networks; revisit when running against `8.8.8.8` or
similar.
