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
    """
    Convert nmap port results into CVE search queries.
    Returns deduplicated list of search keywords.
    """
    queries = set()
    for port in ports:
        service = port.get("service", "").lower()
        if service in SERVICE_KEYWORDS:
            for kw in SERVICE_KEYWORDS[service]:
                queries.add(kw)
        elif service:
            queries.add(service)
    return list(queries)


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
