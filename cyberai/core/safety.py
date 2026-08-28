"""Inspection of tool arguments, in front of the tool rather than the model.

The six patterns that used to live here are gone. They were a second detector
answering the same question as core/security/injection_detector.py, with a
different pattern set and a different verdict, and the two disagreed: this one
knew six patterns against that one's thirty-one. Two answers to one question
is not defence in depth, it is an unresolved disagreement.

What is left is the half of the boundary TrustGuard does not cover. TrustGuard
inspects what reaches a language model, where a suspicious message can still be
sent under a label. A tool argument has nothing to label: the scanner either
runs against the value or it does not, so the verdict has to reach a caller
that can refuse. That decision is made by the sanitize_input decorator; this
module only reports.

Scope enforcement lives in agents/exploit/safety_validator.py, which the
orchestrator calls before the exploit phase.
"""

from typing import Any, Dict, List

from cyberai.core.security.injection_detector import detect_injection


class ToolInputBlocked(ValueError):
    """Raised when a tool argument carries an injection payload.

    Carries the verdict, not just a message. The previous design returned the
    string "[BLOCKED: potential injection in input]" in place of the argument,
    so the tool ran against a placeholder: a TLS scan of that string reports a
    failed handshake against a host that was never the target, and the caller
    has no way to tell that from a real one.
    """

    def __init__(self, categories: List[str], risk_score: int) -> None:
        super().__init__(
            f"tool input blocked: risk={risk_score} categories={','.join(categories) or 'none'}"
        )
        self.categories = categories
        self.risk_score = risk_score


class InputSanitizer:
    """The canonical detector's verdict on a single tool argument."""

    @classmethod
    def inspect(cls, text: str) -> Dict[str, Any]:
        """Report on ``text``. Never rewrites it and never raises."""
        return detect_injection(text)
