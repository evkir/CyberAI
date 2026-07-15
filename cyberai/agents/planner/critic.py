"""Critic agent.

Assesses a failed pipeline phase and decides whether it is worth re-running.
Deterministic and LLM-free: transient-looking failures (timeouts, connection
resets, rate limits) are marked ``retry``; everything else — scope violations,
validation errors, permanent faults — is marked ``skip`` so the pipeline never
loops on an unrecoverable phase. The verdict is stored in the KB.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from cyberai.core.base_agent import BaseAgent

_TRANSIENT_SIGNALS = (
    "timeout",
    "timed out",
    "connection",
    "temporarily",
    "rate limit",
    "429",
    "503",
    "reset by peer",
    "unreachable",
    "try again",
)


class CriticAgent(BaseAgent):
    """Decide retry-vs-skip for a failed phase."""

    AGENT_NAME = "critic"
    ROLE = "Failure Critic"

    def _register_tools(self) -> None:  # no external tools — pure reasoning
        pass

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        context = context or {}
        phase = context.get("phase", "unknown")
        error = str(context.get("error") or "").lower()

        transient = self._is_transient(error)
        decision = "retry" if transient else "skip"
        reason = (
            "transient failure — worth one retry"
            if transient
            else "non-transient failure — skipping"
        )

        verdict = {"phase": phase, "decision": decision, "reason": reason}
        self.session.kb_set(f"critic.{phase}", verdict)
        self.log(f"critic verdict on {phase}: {decision}", verdict)
        return verdict

    @staticmethod
    def _is_transient(error: str) -> bool:
        return any(sig in error for sig in _TRANSIENT_SIGNALS)
