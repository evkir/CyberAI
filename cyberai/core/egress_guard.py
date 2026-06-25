"""
Egress guard for air-gapped mode (day 6 / STANDOFF II W1).

Air-gapped red-team work (NDA, isolated client networks) must not leak target
infrastructure into cloud LLM APIs. This module is the single source of truth
for "is this LLM endpoint local?" and enforces it when air_gapped is on.

Local means one of:
  - provider == "ollama" with a localhost/empty base_url (ollama defaults to
    http://localhost:11434), OR
  - any provider whose base_url resolves to a loopback or RFC-1918 private host
    (covers vLLM / LM Studio / local OpenAI-compatible servers).

A bare openai/anthropic provider with no private base_url hits the public cloud
API and is therefore NOT local — assert_air_gapped raises EgressViolation.

The badge is honest: `Air-Gapped Ready`, not `Zero Data Leakage`. This guard
proves the configured endpoint is local; it does not audit the OS network stack.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from cyberai.core.config import LLMConfig

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_OLLAMA_DEFAULT = "http://localhost:11434"


class EgressViolation(RuntimeError):
    """Raised when air-gapped mode is on but the LLM endpoint is not local."""


def _host_is_private(host: str) -> bool:
    """True for loopback or RFC-1918 private addresses / localhost."""
    if not host:
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a bare IP (e.g. a hostname); only explicit localhost counts local.
        return host == "localhost"
    return ip.is_loopback or ip.is_private


def is_local_endpoint(llm: LLMConfig) -> bool:
    """Decide whether this LLM config talks to a local-only endpoint."""
    base = (llm.base_url or "").strip()

    if llm.provider == "ollama":
        # Empty base_url => ollama default (localhost). Otherwise inspect host.
        if not base:
            return True
        return _host_is_private(urlparse(base).hostname or "")

    # openai/anthropic: local ONLY via an explicit private base_url (vLLM etc.).
    if not base:
        return False
    return _host_is_private(urlparse(base).hostname or "")


def assert_air_gapped(llm: LLMConfig) -> None:
    """Raise EgressViolation unless `llm` is provably a local endpoint."""
    if not is_local_endpoint(llm):
        raise EgressViolation(
            f"air-gapped mode: provider={llm.provider!r} base_url={llm.base_url!r} "
            "is not a local endpoint (loopback/RFC-1918). Set provider='ollama' "
            "or point base_url at a local vLLM/Ollama server."
        )
