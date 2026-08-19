"""
Subdomain enumerator — DNS brute force via wordlist.
Uses concurrent resolution for speed.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import socket
from pathlib import Path
from typing import Any, Dict, List

import dns.asyncresolver

DEFAULT_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "vpn",
    "remote",
    "portal",
    "app",
    "web",
    "secure",
    "mx",
    "ns1",
    "ns2",
    "smtp",
    "pop",
    "imap",
    "cdn",
    "static",
    "media",
    "assets",
    "images",
    "blog",
    "shop",
    "store",
    "beta",
    "alpha",
    "demo",
    "docs",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "monitor",
    "status",
    "dashboard",
    "login",
    "auth",
    "sso",
    "internal",
    "intranet",
    "corp",
    "office",
    "backup",
    "old",
]


def fqdns(result: Dict[str, Any] | None = None) -> List[str]:
    """Extract plain hostnames from an enumerate_subdomains* result.

    Both enumerators return {"found": [{"fqdn": ...}]}. Callers that need
    bare hostnames (ReconResult.subdomains, the planner KB graph) must use
    this instead of re-deriving the shape, or the sync and async pipeline
    paths drift apart silently.
    """
    found = (result or {}).get("found") or []
    return [r["fqdn"] for r in found if isinstance(r, dict) and r.get("fqdn")]


def enumerate_subdomains(
    domain: str,
    wordlist: List[str] = None,
    max_workers: int = 20,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Brute-force subdomains via DNS resolution.

    Args:
        domain:      base domain e.g. "example.com"
        wordlist:    list of prefixes to try
        max_workers: concurrent resolver threads
        timeout:     DNS timeout per query in seconds

    Returns:
        dict with found subdomains and stats
    """
    words = wordlist or DEFAULT_WORDLIST
    targets = [f"{w}.{domain}" for w in words]
    found: List[Dict[str, Any]] = []

    socket.setdefaulttimeout(timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(_resolve, fqdn): fqdn for fqdn in targets}
        for future in concurrent.futures.as_completed(future_map):
            _ = future_map[future]
            try:
                result = future.result()
                if result:
                    found.append(result)
            except Exception:
                pass

    found.sort(key=lambda x: x["fqdn"])

    return {
        "domain": domain,
        "found": found,
        "count": len(found),
        "checked": len(targets),
        "wordlist": words,
    }


def _resolve(fqdn: str) -> Dict[str, Any] | None:
    """Resolve a single FQDN — return result dict or None."""
    try:
        infos = socket.getaddrinfo(fqdn, None)
        ips = list({info[4][0] for info in infos})
        if ips:
            return {
                "fqdn": fqdn,
                "ips": ips,
                "subdomain": fqdn.split(".")[0],
            }
    except (socket.gaierror, socket.herror, OSError):
        pass
    return None


def load_wordlist(path: str) -> List[str]:
    """Load custom wordlist from file — one entry per line."""
    p = Path(path)
    if not p.exists():
        return DEFAULT_WORDLIST
    lines = p.read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


async def _resolve_async(
    resolver: "dns.asyncresolver.Resolver",
    fqdn: str,
    sem: asyncio.Semaphore,
    timeout: float,
) -> Dict[str, Any] | None:
    """Async equivalent of _resolve — gated by semaphore."""
    async with sem:
        try:
            answers = await resolver.resolve(fqdn, "A", lifetime=timeout)
            ips = sorted({str(r) for r in answers})
            if ips:
                return {
                    "fqdn": fqdn,
                    "ips": ips,
                    "subdomain": fqdn.split(".")[0],
                }
        except Exception:
            pass
    return None


async def enumerate_subdomains_async(
    domain: str,
    wordlist: List[str] = None,
    max_concurrent: int = 20,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Async subdomain brute force — drop-in equivalent of enumerate_subdomains.

    Concurrency limited via asyncio.Semaphore so we don't hammer the
    upstream resolver. Same return shape as the sync version.
    """
    words = wordlist or DEFAULT_WORDLIST
    targets = [f"{w}.{domain}" for w in words]
    sem = asyncio.Semaphore(max_concurrent)
    resolver = dns.asyncresolver.Resolver()

    results = await asyncio.gather(
        *(_resolve_async(resolver, fqdn, sem, timeout) for fqdn in targets),
        return_exceptions=False,
    )
    found = [r for r in results if r is not None]
    found.sort(key=lambda x: x["fqdn"])

    return {
        "domain": domain,
        "found": found,
        "count": len(found),
        "checked": len(targets),
        "wordlist": words,
    }
