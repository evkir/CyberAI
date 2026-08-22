"""The single trust boundary in front of a language model.

Every message that reaches a provider passes through TrustGuard.inspect().
Before this module existed, the sanitisers in this package had unit tests and
no callers: the detector ran on phase *output*, after the agent had already
talked to the model. Scanning what came back is auditing, not guarding.

Three policies, chosen by CYBERAI_INJECTION_POLICY:

``annotate`` (default)
    Wrap suspicious content in an explicit untrusted marker, send it, record
    the verdict. The model still sees the data; it sees it labelled as data.

``quarantine``
    Wrap, redact each matched pattern to ``[REDACTED:<category>]``, and cap the
    remainder at MAX_BANNER_LENGTH before sending.

``deny``
    Raise InjectionBlocked. No request is made to the provider.

Why annotate is the default and quarantine is not, despite quarantine being
the safer-sounding choice: measured on 43 real scan reports the current
detector flags 42, and on audit events carrying prompt payloads it flags 25 of
100 — every one of them on ``<!--...-->`` in a captured HTML body. A policy
that mutates content must not run on a detector with that false-positive rate,
or the product silently corrupts its own legitimate input. Quarantine becomes
the default once the detector is rebuilt and has published precision numbers.

The threshold default of 50 comes from the same measurement. Scores on that
corpus are bimodal — 75 events at 0 and 25 at exactly 25, nothing between —
because risk_score is len(matches) * 25 and the false positives all match a
single category. A threshold of 50 therefore requires two independent
categories to agree before the guard acts, and costs nothing in recall
against anything the current detector can actually see.

Both figures carry a caveat and are not to be quoted without it. They were
taken while inspect() scored the *sanitised* copy, so three of the detector's
categories could not appear in them at all, and the corpus they were taken on
is not tracked in the repository and no longer exists on the machine that
produced it. They are therefore a lower bound on the true score distribution,
kept here as the recorded reason for the current defaults rather than as a
reproducible measurement. W3 rebuilds the detector against a tracked eval
corpus and republishes precision and recall; the threshold is revisited there,
not before.

System prompts are never touched. Only user, tool and function messages are
attacker-reachable; rewriting our own instructions would be a defect, not a
defence.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List

from cyberai.core.security.injection_detector import COMPILED_PATTERNS, detect_injection
from cyberai.core.security.input_sanitizer import MAX_BANNER_LENGTH, sanitize_llm_input

ANNOTATE = "annotate"
QUARANTINE = "quarantine"
DENY = "deny"
POLICIES = (ANNOTATE, QUARANTINE, DENY)

DEFAULT_POLICY = ANNOTATE
DEFAULT_THRESHOLD = 50

UNTRUSTED_OPEN = "[UNTRUSTED INPUT]"
UNTRUSTED_CLOSE = "[/UNTRUSTED INPUT]"

UNTRUSTED_ROLES = ("user", "tool", "function")


class InjectionBlocked(RuntimeError):
    """Raised under the deny policy. The provider is never contacted."""

    def __init__(self, verdict: "GuardVerdict") -> None:
        super().__init__(
            f"injection blocked: risk={verdict.risk_score} "
            f"categories={','.join(verdict.categories) or 'none'}"
        )
        self.verdict = verdict


@dataclass
class GuardVerdict:
    """What the guard decided, and the messages it is willing to send.

    ``risk_score`` is None when nothing was inspectable — no untrusted message
    in the batch. A default of 0 would claim "measured, and clean" about a
    batch that was never measured.
    """

    policy: str
    threshold: int
    triggered: bool
    risk_score: int | None
    categories: List[str]
    messages: List[Dict[str, Any]]
    inspected: int
    modified: int

    def as_event(self) -> Dict[str, Any]:
        """The shape written to the audit log. Message bodies stay out of it."""
        return {
            "policy": self.policy,
            "threshold": self.threshold,
            "triggered": self.triggered,
            "risk_score": self.risk_score,
            "categories": self.categories,
            "inspected": self.inspected,
            "modified": self.modified,
        }


def policy_from_env() -> str:
    """Read the policy at call time, not at import time."""
    raw = os.getenv("CYBERAI_INJECTION_POLICY", DEFAULT_POLICY).strip().lower()
    return raw if raw in POLICIES else DEFAULT_POLICY


def threshold_from_env() -> int:
    raw = os.getenv("CYBERAI_INJECTION_THRESHOLD", "")
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_THRESHOLD


def _redact(text: str) -> str:
    """Replace every matched pattern with a labelled placeholder.

    Substitution runs off the compiled patterns rather than off the strings in
    ``matches``: findall returns capture groups when a pattern has any, so the
    reported fragment is not always the text that matched.
    """
    out = text
    for pattern, label in COMPILED_PATTERNS:
        out = pattern.sub(f"[REDACTED:{label}]", out)
    return out


def _wrap(text: str) -> str:
    if text.startswith(UNTRUSTED_OPEN):
        return text
    return f"{UNTRUSTED_OPEN} {text} {UNTRUSTED_CLOSE}"


class TrustGuard:
    """The choke point. Constructed per LLMClient, consulted per call."""

    def __init__(self, policy: str | None = None, threshold: int | None = None) -> None:
        self.policy = policy if policy in POLICIES else policy_from_env()
        # isinstance, not 'is not None': the threshold ends up in a
        # numeric comparison inside the boundary, so a non-integer here
        # raises TypeError in the middle of guarding a call rather than
        # at construction. Policy already degrades to the default on a
        # bad value; the threshold now behaves the same way. bool is an
        # int subclass and is not a threshold.
        if isinstance(threshold, int) and not isinstance(threshold, bool):
            self.threshold = threshold
        else:
            self.threshold = threshold_from_env()

    def inspect(self, messages: List[Dict[str, Any]]) -> GuardVerdict:
        """Return the verdict and the messages that may be sent."""
        worst: int | None = None
        categories: List[str] = []
        flagged: List[int] = []

        # Detection runs on the raw messages, sanitisation afterwards. The
        # reverse order was measured to blind the detector: sanitize_text
        # strips {{ }} and <|im_start|>/<|im_end|>, which are three of the
        # detector's own categories (template_injection, context_manipulation
        # x2). A payload carrying them scored 75 raw and 25 through the guard,
        # so adding a template marker to an injection *lowered* its score and
        # carried it under the threshold. Sanitise what is sent; score what
        # arrived.
        for i, msg in enumerate(messages):
            if msg.get("role") not in UNTRUSTED_ROLES:
                continue
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue
            result = detect_injection(content)
            score = result["risk_score"]
            worst = score if worst is None else max(worst, score)
            if score >= self.threshold:
                flagged.append(i)
                for match in result["matches"]:
                    if match["type"] not in categories:
                        categories.append(match["type"])

        cleaned = sanitize_llm_input(messages)

        triggered = bool(flagged)
        verdict = GuardVerdict(
            policy=self.policy,
            threshold=self.threshold,
            triggered=triggered,
            risk_score=worst,
            categories=sorted(categories),
            messages=cleaned,
            inspected=sum(1 for m in cleaned if m.get("role") in UNTRUSTED_ROLES),
            modified=0,
        )

        if not triggered:
            return verdict

        if self.policy == DENY:
            raise InjectionBlocked(verdict)

        for i in flagged:
            content = cleaned[i].get("content", "")
            if self.policy == QUARANTINE:
                content = _redact(content)[:MAX_BANNER_LENGTH]
            cleaned[i] = {**cleaned[i], "content": _wrap(content)}

        verdict.modified = len(flagged)
        return verdict
