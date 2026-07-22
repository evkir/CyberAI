import shlex
import subprocess
from typing import Any, Dict, List

from cyberai.core.security.input_sanitizer import sanitize_target
from cyberai.core.cache import FileCache
from pathlib import Path

# Whitelist of nmap flags the toolkit is allowed to pass through.
# Anything outside this set is rejected — prevents abuse like
# -oN /etc/cron.d/x, --script=<malicious>, or arbitrary file writes.
ALLOWED_FLAGS = {
    "-sV",
    "-sC",
    "-sT",
    "-sS",
    "-sU",
    "-sn",
    "-T0",
    "-T1",
    "-T2",
    "-T3",
    "-T4",
    "-T5",
    "-Pn",
    "-A",
    "-O",
    "-p",
    "--top-ports",
    "-oX",
}

# Flags that consume the next token as a value (port spec, count, etc.).
_VALUE_FLAGS = {"-p", "--top-ports", "-oX"}

# Dedicated 1-hour cache for nmap results, keyed by target+flags.
# Avoids re-scanning the same target repeatedly within a session.
NMAP_CACHE_TTL = 3600  # 1 hour
_nmap_cache = FileCache(
    cache_dir=Path.home() / ".cyberai" / "nmap-cache",
    ttl=NMAP_CACHE_TTL,
)


def _cache_key(target: str, flags: str) -> str:
    return f"nmap:{target}:{flags}"


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


DEFAULT_NMAP_TIMEOUT = 180
# Time budget for the scoped -sV re-probe of the discovered open ports.
_TARGETED_SV_TIMEOUT = 90
# Above this many open ports a scan is treated as untrustworthy: real
# hosts do not hold hundreds of the top-1000 ports open, so such a result
# is the signature of a fake-ip proxy, tunnel, or tarpit answering every
# probe rather than a genuine attack surface.
_MASS_OPEN_THRESHOLD = 100


def _exec_nmap(
    safe_target: str, safe_flags: List[str], timeout: int, target: str
) -> Dict[str, Any]:
    """Run one nmap invocation. Error dicts always carry an empty ``ports``
    list so downstream consumers get a consistent shape."""
    # --noninteractive: nmap's runtime keypress reader opens /dev/tty directly
    # (independent of stdin) and can leave the terminal in no-echo/raw mode.
    # This flag disables it outright. stdin=DEVNULL is kept as belt-and-braces.
    cmd = ["nmap", "-oX", "-", "--noninteractive"] + safe_flags + [safe_target]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return {
            "target": target,
            "raw": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "ports": _parse_ports(result.stdout),
            "cached": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "error": f"nmap timeout after {timeout}s",
            "timed_out": True,
            "ports": [],
        }
    except FileNotFoundError:
        return {
            "target": target,
            "error": "nmap not found — install with: apt install nmap",
            "ports": [],
        }


def _open_port_nums(parsed: Dict[str, Any]) -> List[int]:
    """Port numbers of the open ports in a parsed nmap result."""
    return [
        p["port"]
        for p in parsed.get("ports", [])
        if p.get("state") == "open" and isinstance(p.get("port"), int)
    ]


def _has_products(parsed: Dict[str, Any]) -> bool:
    """True when -sV captured at least one product string. Mirrors the intel
    layer's ``version_known`` check so the degraded marker and the severity
    gate agree on what counts as a known version."""
    return any((p.get("product") or "").strip() for p in parsed.get("ports", []))


def _strip_sv(flags: List[str]) -> List[str]:
    """Return the validated flag list without the ``-sV`` token, for a fast
    version-less discovery pass. Port scope and timing flags are preserved."""
    return [t for t in flags if t != "-sV"]


def _mark_mass_open(parsed: Dict[str, Any]) -> bool:
    """Flag implausible mass-open results (fake-ip proxy / tunnel / tarpit).

    Real hosts do not hold hundreds of the top-1000 ports open, so such a
    result is treated as untrustworthy: the intel layer skips a meaningless
    CVE spray over noise ports rather than gambling query budget on garbage
    service names. Returns True when the scan was flagged."""
    open_count = len(_open_port_nums(parsed))
    if open_count > _MASS_OPEN_THRESHOLD:
        parsed["mass_open"] = True
        parsed["open_count"] = open_count
        return True
    return False


def run_nmap(
    target: str,
    flags: str = "-sV -T4 --top-ports 1000",
    timeout: int = DEFAULT_NMAP_TIMEOUT,
) -> Dict[str, Any]:
    """
    Run nmap against target, return parsed results.
    Requires nmap installed on system.

    When ``-sV`` is requested a fast version-less discovery pass runs first; an
    implausible mass-open result (fake-ip proxy / tunnel / tarpit) is flagged
    before any ``-sV`` so no version spray hits phantom ports, and a scoped
    ``-sV`` re-probe recovers versions on the ports that are genuinely open.
    Explicit non-``-sV`` scans run unchanged as a single pass.
    """
    safe_target = sanitize_target(target)
    try:
        safe_flags = validate_flags(flags)
    except ValueError as exc:
        return {"target": target, "error": f"unsafe nmap flags: {exc}", "ports": []}

    cache_key = _cache_key(safe_target, flags)
    cached = _nmap_cache.get(cache_key)
    if cached is not None:
        cached["cached"] = True
        return cached

    # Discovery-first. -sV service probing is the slow, fragile part: against a
    # fake-ip proxy, tunnel, or tarpit it sprays version probes across hundreds
    # of phantom "open" ports, burning minutes and destabilising the local
    # resolver. So when -sV is requested we run a fast version-less discovery
    # pass, flag an implausible mass-open result BEFORE any -sV, and re-probe
    # -sV scoped only to the ports that are genuinely open on a trustworthy
    # result. When the scoped -sV yields no product (filtering net, no banners)
    # the discovery result is returned marked degraded, which the intel layer
    # treats as "service versions unknown" and gates accordingly. A caller
    # passing explicit non-sV flags runs unchanged as a single scan.
    if "-sV" in safe_flags:
        disco = _exec_nmap(safe_target, _strip_sv(safe_flags), min(timeout, 60), target)
        if _mark_mass_open(disco):
            parsed = disco  # tunnel / fake-ip / tarpit — skip -sV, no spray
        else:
            open_nums = _open_port_nums(disco)
            if open_nums:
                pspec = ",".join(str(n) for n in open_nums)
                sv_flags = validate_flags(f"-sV -T4 -p {pspec}")
                scoped = _exec_nmap(safe_target, sv_flags, _TARGETED_SV_TIMEOUT, target)
                parsed = scoped if scoped.get("ports") else disco
            else:
                parsed = disco
            if not _has_products(parsed):
                parsed["degraded"] = "sV_timeout_fast_retry"
    else:
        parsed = _exec_nmap(safe_target, safe_flags, timeout, target)
        _mark_mass_open(parsed)

    if parsed.get("returncode") == 0:
        _nmap_cache.set(cache_key, parsed)
    return parsed


def _svc_attr(attrs: str, key: str) -> str:
    """Pull a single attribute value from a raw nmap <service> tag body."""
    import re

    m = re.search(rf'\b{key}="([^"]*)"', attrs)
    return m.group(1) if m else ""


def _parse_ports(xml_output: str) -> list:
    """Extract open ports from nmap XML output.

    Captures product/version from -sV so downstream CVE matching can be
    version-aware instead of querying by bare service name (which pulls in
    ancient, non-applicable CVEs and inflates severity).
    """
    import re

    ports = []
    for match in re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)">.*?'
        r'<state state="(\w+)".*?/>.*?'
        r"<service ([^>]*)",
        xml_output,
        re.DOTALL,
    ):
        proto, port, state, svc_attrs = match.groups()
        if state == "open":
            ports.append(
                {
                    "port": int(port),
                    "protocol": proto,
                    "service": _svc_attr(svc_attrs, "name"),
                    "product": _svc_attr(svc_attrs, "product"),
                    "version": _svc_attr(svc_attrs, "version"),
                    "state": state,
                }
            )
    return ports
