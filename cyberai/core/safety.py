"""
Multi-agent safety protocol.
Scope validation + input sanitization + trust boundaries.
"""
import ipaddress
import re
from typing import List
from dataclasses import dataclass, field


@dataclass
class ScopeConfig:
    allowed_ips: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    excluded_ips: List[str] = field(default_factory=list)
    authorized: bool = False


class ScopeValidator:
    def __init__(self, scope: ScopeConfig):
        self.scope = scope

    def is_in_scope(self, target: str) -> bool:
        if not self.scope.authorized:
            return False
        for allowed in self.scope.allowed_ips:
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(allowed, strict=False):
                    return True
            except ValueError:
                pass
        for domain in self.scope.allowed_domains:
            if target == domain or target.endswith(f".{domain}"):
                return True
        return False


class InputSanitizer:
    DANGEROUS_PATTERNS = [
        r"ignore\s+previous\s+instructions",
        r"you\s+are\s+now",
        r"act\s+as",
        r"jailbreak",
        r"<\s*script",
        r"javascript:",
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return "[BLOCKED: potential injection in input]"
        return text[:10000]


class AgentTrustBoundary:
    AGENT_KB_PERMISSIONS = {
        "recon":        ["recon"],
        "intel":        ["intel"],
        "exploit":      ["exploit"],
        "report":       ["report"],
        "orchestrator": ["recon", "intel", "exploit", "report", "meta"],
    }

    @classmethod
    def can_write(cls, agent: str, key: str) -> bool:
        allowed = cls.AGENT_KB_PERMISSIONS.get(agent, [])
        return any(key.startswith(k) for k in allowed)

    @classmethod
    def validate_write(cls, agent: str, key: str):
        if not cls.can_write(agent, key):
            raise PermissionError(
                f"Agent '{agent}' not allowed to write to KB key '{key}'"
            )
