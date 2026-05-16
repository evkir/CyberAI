"""
Graceful nmap timeout wrapper for ReconAgent.
Returns partial results instead of crashing on timeout.
"""
import subprocess
import logging
from typing import Optional

logger = logging.getLogger("cyberai.recon.nmap_wrapper")


def run_nmap_safe(
    target: str,
    flags: str = "-sV -T4 --top-ports 1000",
    timeout: int = 120,
) -> dict:
    """
    Run nmap with timeout. On timeout returns partial/empty result
    instead of raising — pipeline continues with what we have.

    Returns:
        dict with 'ports', 'raw', 'error' (if any), 'timed_out' flag
    """
    cmd = ["nmap"] + flags.split() + [target]
    logger.info(f"[nmap] running: {' '.join(cmd)} (timeout={timeout}s)")

    result = {
        "target": target,
        "ports": [],
        "services": {},
        "raw": "",
        "timed_out": False,
        "error": None,
    }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result["raw"] = proc.stdout
        result["ports"] = _parse_ports(proc.stdout)
        result["services"] = _parse_services(proc.stdout)

    except subprocess.TimeoutExpired:
        logger.warning(f"[nmap] timeout after {timeout}s for {target} — returning partial")
        result["timed_out"] = True
        result["error"] = f"nmap timed out after {timeout}s"

    except FileNotFoundError:
        logger.error("[nmap] nmap not found — install with: apt install nmap")
        result["error"] = "nmap binary not found"

    except Exception as e:
        logger.error(f"[nmap] unexpected error: {e}")
        result["error"] = str(e)

    return result


def _parse_ports(output: str) -> list[int]:
    ports = []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            try:
                ports.append(int(line.split("/")[0].strip()))
            except ValueError:
                pass
    return ports


def _parse_services(output: str) -> dict[str, str]:
    services = {}
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0].split("/")[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                services[port] = service
    return services
