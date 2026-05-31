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
