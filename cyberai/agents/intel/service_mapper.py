import re
from typing import List, Dict

# Map common services to better NVD search keywords
SERVICE_KEYWORDS = {
    "http": ["apache httpd", "nginx", "iis"],
    "https": ["apache httpd", "nginx", "openssl"],
    "ssh": ["openssh"],
    "ftp": ["vsftpd", "proftpd", "filezilla server"],
    "smtp": ["postfix", "sendmail", "exim"],
    "smb": ["samba", "windows smb"],
    "rdp": ["remote desktop", "rdp"],
    "mysql": ["mysql", "mariadb"],
    "postgres": ["postgresql"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "tomcat": ["apache tomcat"],
    "jenkins": ["jenkins"],
    "docker": ["docker"],
    "vnc": ["vnc server"],
}


def ports_to_queries(ports: List[Dict]) -> List[str]:
    """Convert nmap port results into CVE search queries.

    Returns a deterministic, priority-ordered list: keyword-mapped product
    queries (e.g. "openssh", "apache httpd") come first so a limited query
    budget is spent on recognizable services before raw, unmapped service
    names. Order follows port iteration (ascending port number from nmap);
    duplicates are dropped while preserving first-seen position. A previous
    set()-based build returned queries in nondeterministic order, so a
    truncated budget could miss real services (e.g. openssh) on hosts with
    many ports.
    """
    mapped: List[str] = []
    raw: List[str] = []
    seen: set = set()
    for port in ports:
        service = (port.get("service") or "").lower()
        if service in SERVICE_KEYWORDS:
            for kw in SERVICE_KEYWORDS[service]:
                if kw not in seen:
                    seen.add(kw)
                    mapped.append(kw)
        elif service:
            if service not in seen:
                seen.add(service)
                raw.append(service)
    return mapped + raw


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def product_tokens(ports: List[Dict]) -> set:
    """Lowercased product/service tokens used to check CVE relevance.

    Built from nmap -sV product names (service name as fallback) so a CVE
    surfaced from a broad keyword query can be checked against what is
    actually running. Empty when no product/service info is available, in
    which case relevance filtering is skipped (no-regression).
    """
    tokens: set = set()
    for port in ports:
        for field in ("product", "service"):
            val = (port.get(field) or "").lower()
            for tok in re.split(r"[^a-z0-9]+", val):
                if len(tok) >= 3:  # drop version noise like "d", "v2"
                    tokens.add(tok)
    return tokens


def cve_is_relevant(description: str, tokens: set) -> bool:
    """True if there is no product signal (cannot filter) or the CVE
    description mentions a detected product/service token.

    Guards against cross-product keyword collisions — e.g. a sendmail CVE
    surfacing for an Apache/OpenSSH host because the http keyword query
    happened to return it.
    """
    if not tokens:
        return True
    text = (description or "").lower()
    return any(tok in text for tok in tokens)
