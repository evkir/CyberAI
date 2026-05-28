import shlex
import subprocess
from typing import Any, Dict, List

from cyberai.core.security.input_sanitizer import sanitize_target

# Whitelist of nmap flags the toolkit is allowed to pass through.
# Anything outside this set is rejected — prevents abuse like
# -oN /etc/cron.d/x, --script=<malicious>, or arbitrary file writes.
ALLOWED_FLAGS = {
    "-sV", "-sC", "-sT", "-sS", "-sU", "-sn",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "-Pn", "-A", "-O",
    "-p", "--top-ports", "-oX",
}

# Flags that consume the next token as a value (port spec, count, etc.).
_VALUE_FLAGS = {"-p", "--top-ports", "-oX"}


def validate_flags(flags: str) -> List[str]:
    """Parse a flag string via shlex and reject anything not whitelisted.

    Returns the validated token list. Raises ValueError on the first
    unknown flag so a malicious flag string never reaches subprocess.
    """
    tokens = shlex.split(flags)
    safe: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok not in ALLOWED_FLAGS:
            raise ValueError(f"Rejected nmap flag: {tok!r}")
        safe.append(tok)
        if tok in _VALUE_FLAGS and i + 1 < len(tokens):
            safe.append(tokens[i + 1])
            i += 1
        i += 1
    return safe

def run_nmap(target: str, flags: str = "-sV -T4 --top-ports 1000") -> Dict[str, Any]:
    """
    Run nmap against target, return parsed results.
    Requires nmap installed on system.
    """
    safe_target = sanitize_target(target)
    try:
        safe_flags = validate_flags(flags)
    except ValueError as exc:
        return {"target": target, "error": f"unsafe nmap flags: {exc}"}

    cmd = ["nmap", "-oX", "-"] + safe_flags + [safe_target]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        return {
            "target": target,
            "raw": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "ports": _parse_ports(result.stdout),
        }
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "nmap timeout after 120s"}
    except FileNotFoundError:
        return {"target": target, "error": "nmap not found — install with: apt install nmap"}

def _parse_ports(xml_output: str) -> list:
    """Extract open ports from nmap XML output"""
    import re
    ports = []
    for match in re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)">.*?'
        r'<state state="(\w+)".*?/>.*?'
        r'<service name="([^"]*)"',
        xml_output, re.DOTALL
    ):
        proto, port, state, service = match.groups()
        if state == "open":
            ports.append({
                "port": int(port),
                "protocol": proto,
                "service": service,
                "state": state,
            })
    return ports

