"""Name and registration lookups for a target, sync and async.

The sync pair is what a single-target run uses; the async path exists for a
sweep, where the cost is waiting on a resolver rather than computing anything.
Both answer the same questions and return the same shape, so a caller can
switch on breadth alone.

A failed lookup is an answer here, not an error. A target with no PTR and no
whois record is a fact about the target, and raising would make the agent
above treat it as a broken tool.
"""

import asyncio
from typing import Any, Dict, List

import dns.asyncresolver
import dns.resolver
import whois


def run_whois(target: str) -> Dict[str, Any]:
    """Run whois lookup on target domain"""
    try:
        w = whois.whois(target)
        return {
            "target": target,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        return {"target": target, "error": str(e)}


def run_dns(target: str) -> Dict[str, Any]:
    """Enumerate DNS records for target"""
    results: Dict[str, Any] = {"target": target, "records": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            results["records"][rtype] = [str(r) for r in answers]
        except Exception:
            results["records"][rtype] = []

    return results


async def _query_one(resolver: "dns.asyncresolver.Resolver", target: str, rtype: str) -> List[str]:
    """Resolve a single record type; return [] on any failure (matches sync behaviour)."""
    try:
        answers = await resolver.resolve(target, rtype, lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


async def run_dns_async(target: str) -> Dict[str, Any]:
    """
    Async DNS enumeration — resolves A/AAAA/MX/NS/TXT/CNAME/SOA concurrently.

    Drop-in async equivalent of `run_dns`; same return shape.
    """
    resolver = dns.asyncresolver.Resolver()
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    answers = await asyncio.gather(*(_query_one(resolver, target, rt) for rt in record_types))

    return {
        "target": target,
        "records": dict(zip(record_types, answers)),
    }
