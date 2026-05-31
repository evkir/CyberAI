import dns.resolver
import whois
from typing import Dict, Any, List


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


def detect_subdomains(target: str, wordlist: List[str] = None) -> Dict[str, Any]:
    """Basic subdomain bruteforce from wordlist"""
    if wordlist is None:
        wordlist = [
            "www",
            "mail",
            "ftp",
            "admin",
            "api",
            "dev",
            "staging",
            "vpn",
            "remote",
            "portal",
            "app",
        ]
    found = []
    for sub in wordlist:
        host = f"{sub}.{target}"
        try:
            dns.resolver.resolve(host, "A", lifetime=3)
            found.append(host)
        except Exception:
            pass
    return {"target": target, "subdomains": found}
