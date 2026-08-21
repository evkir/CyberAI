"""
Input sanitisation for tool arguments.

Scope enforcement lives in agents/exploit/safety_validator.py, which the
orchestrator calls before the exploit phase. The scope and trust-boundary
classes that once sat here had no call site and were removed.
"""

import re


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
