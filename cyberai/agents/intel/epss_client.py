"""EPSS (Exploit Prediction Scoring System) client — api.first.org.

EPSS gives a probability (0.0-1.0) that a CVE will be exploited in the
wild in the next 30 days. Updated daily by FIRST.org. Free, no API key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import httpx

from cyberai.core.cache import FileCache

EPSS_BASE = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100
EPSS_CACHE_TTL = 3600 * 24  # 24h — EPSS recomputes once a day

_epss_cache = FileCache(
    cache_dir=Path.home() / ".cyberai" / "epss-cache",
    ttl=EPSS_CACHE_TTL,
)


def get_epss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs.

    Batches in groups of 100, caches per-CVE for 24h. CVEs not covered
    by EPSS silently get 0.0. HTTP failures degrade to 0.0 — the
    pipeline must survive an EPSS outage.
    """
    if not cve_ids:
        return {}

    scores: Dict[str, float] = {}
    to_fetch: List[str] = []

    # 1. cache lookup
    for cid in cve_ids:
        hit = _epss_cache.get(f"epss:{cid}")
        if hit is not None:
            scores[cid] = float(hit)
        else:
            to_fetch.append(cid)

    # 2. fetch missing in batches
    for i in range(0, len(to_fetch), EPSS_BATCH_SIZE):
        batch = to_fetch[i : i + EPSS_BATCH_SIZE]
        try:
            resp = httpx.get(
                EPSS_BASE,
                params={"cve": ",".join(batch)},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
        except Exception:
            # Silent fallback — every CVE in this batch -> 0.0, no cache.
            for cid in batch:
                scores.setdefault(cid, 0.0)
            continue

        seen = set()
        for row in data:
            cid = row.get("cve")
            epss = float(row.get("epss") or 0.0)
            if cid:
                scores[cid] = epss
                _epss_cache.set(f"epss:{cid}", epss)
                seen.add(cid)

        # CVEs the API didn't return — default to 0.0 without caching
        # (they might be added to EPSS later).
        for cid in batch:
            if cid not in seen:
                scores.setdefault(cid, 0.0)

    return scores
