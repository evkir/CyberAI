"""
Success-criteria evaluator for the local target suite.

Given a running target and the exploitation *evidence* the engine produced
(HTTP responses, command output, file contents), decide whether the target was
actually exploited. Checks are per-vulnerability-class and deliberately binary:
a target is solved only when a concrete, unambiguous signal is present — never
on a heuristic. This keeps pass@1 honest.

Evidence-based checks (`*_from_evidence`) are pure and fully testable; the
optional `probe_*` helpers issue real HTTP via httpx for live runs and are the
only part that touches the network.
"""

from __future__ import annotations

import logging

import httpx

from cyberai.bench.targets import VulnClass, VulnTarget

logger = logging.getLogger("cyberai.bench.evaluator")

DEFAULT_TIMEOUT = 10

# Unambiguous success markers baked into our own apps.
_SQLI_FLAG = "FLAG{sqli-auth-bypass}"
_TRAVERSAL_SECRET = "/etc/bench_flag"


def sqli_solved_from_evidence(response_body: str) -> bool:
    """SQLi target is solved iff the auth-bypass flag leaked in a response."""
    return _SQLI_FLAG in response_body


def cmdi_solved_from_evidence(command_output: str, marker: str) -> bool:
    """CMDi is solved iff our injected marker appears in the command output.

    `marker` is a unique token the caller injected (e.g. via `; echo <token>`),
    proving arbitrary command execution rather than a normal ping reply.
    """
    return bool(marker) and marker in command_output


def traversal_solved_from_evidence(file_contents: str, secret_token: str) -> bool:
    """Path traversal is solved iff out-of-web-root secret content was read."""
    return bool(secret_token) and secret_token in file_contents


def evaluate(target: VulnTarget, evidence: str, marker: str = "") -> bool:
    """Dispatch to the per-class check. `evidence` is whatever the engine got
    back; `marker` is the unique token for classes that need one (CMDi/traversal).
    Unknown classes return False (never a false-positive solve)."""
    vc = target.vuln_class
    if vc is VulnClass.SQLI:
        return sqli_solved_from_evidence(evidence)
    if vc is VulnClass.COMMAND_INJECTION:
        return cmdi_solved_from_evidence(evidence, marker or "cyberai-cmdi-marker")
    if vc is VulnClass.PATH_TRAVERSAL:
        return traversal_solved_from_evidence(evidence, marker or _TRAVERSAL_SECRET)
    logger.info("no evaluator for class %s; treating as unsolved", vc.value)
    return False


def probe_sqli(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Live check: classic ' OR '1'='1 auth bypass against /login."""
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.post(
                f"{base_url}/login",
                data={"username": "admin' -- ", "password": "x"},
            )
        return sqli_solved_from_evidence(r.text)
    except httpx.HTTPError as exc:
        logger.warning("probe_sqli failed: %s", exc)
        return False


def probe_cmdi(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Live check: shell metacharacter injection in /ping?host=.

    Injects `; echo <marker>` so the marker only appears if the host field is
    passed to a shell — proving command injection, not a normal ping reply.
    """
    marker = "cyberai-cmdi-marker"
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(f"{base_url}/ping", params={"host": f"127.0.0.1; echo {marker}"})
        return cmdi_solved_from_evidence(r.text, marker)
    except httpx.HTTPError as exc:
        logger.warning("probe_cmdi failed: %s", exc)
        return False


def probe_traversal(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Live check: ../ escape in /file?name= reads an out-of-web-root secret."""
    try:
        with httpx.Client(timeout=timeout) as client:
            r = client.get(f"{base_url}/file", params={"name": "../../../../etc/bench_flag"})
        return traversal_solved_from_evidence(r.text, _TRAVERSAL_SECRET)
    except httpx.HTTPError as exc:
        logger.warning("probe_traversal failed: %s", exc)
        return False


def probe_for(target: VulnTarget, base_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Dispatch to the per-class live probe. Unknown class => unsolved."""
    vc = target.vuln_class
    if vc is VulnClass.SQLI:
        return probe_sqli(base_url, timeout)
    if vc is VulnClass.COMMAND_INJECTION:
        return probe_cmdi(base_url, timeout)
    if vc is VulnClass.PATH_TRAVERSAL:
        return probe_traversal(base_url, timeout)
    logger.info("no live probe for class %s; unsolved", vc.value)
    return False
