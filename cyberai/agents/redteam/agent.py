"""Red-team agent: drive the injection corpus at planned LLM channels.

The fuzzer is transport-agnostic — it maps a payload string to a response
string and knows nothing about HTTP. This agent supplies the missing half: it
reads the LLM/RAG endpoints the planner named, builds an HTTP channel for
each, and records what the fuzzer confirms as findings on the session.

Confirmation tiers come straight from the fuzzer and are not re-interpreted
here: an out-of-band callback is the only thing that earns full confidence,
and an echoed marker or a leak heuristic stays below it. Promoting a
heuristic to a confirmed finding is exactly the false positive the OOB path
exists to avoid.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

import httpx

from cyberai.core.base_agent import BaseAgent

from .fuzzer import FuzzReport, LLMChannelFuzzer

DEFAULT_TIMEOUT = 10.0

# Field names chat and RAG APIs commonly accept for the user's turn. The
# payload is sent under each in one body: a wrong key is ignored, a right one
# is read, and one request beats probing the schema.
_PROMPT_FIELDS = ("prompt", "message", "input", "query", "text")


def _body_for(prompt_field: Optional[str], payload: str) -> Dict[str, Any]:
    """Build the request body for a channel whose contract may be known.

    Recon names the field when it found the endpoint on the web surface; the
    shotgun over `_PROMPT_FIELDS` is the fallback for channels discovered by
    the path detector, which cannot know it. The shotgun is not harmless: on
    Juice Shop every one of the five guessed names is ignored and the target
    answers that messages must not be empty, so a run that looks delivered
    carries nothing.

    A field named `messages` takes the chat-completions list rather than a
    bare string -- sending the string yields "messages.some is not a
    function". The special case is keyed on the field name, not the target.
    """
    if not prompt_field:
        return {field: payload for field in _PROMPT_FIELDS}
    if prompt_field == "messages":
        return {"messages": [{"role": "user", "content": payload}]}
    return {prompt_field: payload}


def _channel_for(
    url: str,
    prompt_field: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], str]:
    """Return a send function that POSTs to `url`, honouring a known field."""

    def _send(payload: str) -> str:
        body = _body_for(prompt_field, payload)
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                return client.post(url, json=body).text
        except Exception:
            return ""

    return _send


def _default_channel(url: str) -> Callable[[str], str]:
    """Return a send function for a channel whose contract is unknown.

    Kept as a one-argument callable because that is the shape every caller
    supplies a factory in; the contract-aware variant is `_channel_for`.
    """
    return _channel_for(url)


class RedTeamAgent(BaseAgent):
    """Fuzz the LLM channels a plan names; record confirmed injections."""

    AGENT_NAME = "redteam"
    ROLE = "LLM Red Team"

    def _register_tools(self) -> None:  # channels are driven directly
        pass

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._check_iteration_limit()
        channels = self._planned_channels()
        if not channels:
            self._log("No injection-fuzz subtasks in plan — red team skipped")
            return {"channels": 0, "confirmed": 0, "reports": []}

        fuzzer = (context or {}).get("fuzzer") or LLMChannelFuzzer()
        channel_factory = (context or {}).get("channel_factory")

        reports: List[Dict[str, Any]] = []
        confirmed = 0
        for channel in channels:
            url = channel["url"]
            # The contract is bound here rather than passed to the factory:
            # a factory is a one-argument callable everywhere it is supplied,
            # and widening that signature would break every caller that hands
            # one in to keep a test off the network.
            field = channel.get("prompt_field")
            if channel_factory is not None:
                send_fn = channel_factory(url)
            elif field:
                send_fn = _channel_for(url, field)
            else:
                send_fn = _default_channel(url)
            report = fuzzer.fuzz_channel(send_fn, channel_id=url)
            confirmed += report.confirmed_count
            self._record(report, url)
            reports.append(report.to_dict())

        self.kb.set("redteam.reports", reports, agent=self.AGENT_NAME)
        self._log(f"fuzzed {len(channels)} channel(s), {confirmed} confirmed")
        return {"channels": len(channels), "confirmed": confirmed, "reports": reports}

    def _planned_channels(self) -> List[Dict[str, Any]]:
        """Channels from injection-fuzz subtasks, in plan order, deduplicated.

        Each entry keeps the contract the plan carries, not just the URL: the
        field name is what makes the difference between a payload the target
        reads and one it ignores.
        """
        plan = self.kb.get("plan") or {}
        todo = plan.get("todo") if isinstance(plan, dict) else None
        if not isinstance(todo, list):
            return []
        channels: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for task in todo:
            if not isinstance(task, dict) or task.get("action") != "injection-fuzz":
                continue
            url = task.get("target")
            if not url or str(url) in seen:
                continue
            seen.add(str(url))
            channels.append({"url": str(url), "prompt_field": task.get("prompt_field")})
        return channels

    def _record(self, report: FuzzReport, url: str) -> None:
        """Turn fuzz results into session findings, one per signal."""
        from cyberai.core.scan_session import Severity

        for result in report.results:
            if result.severity == "INFO":
                continue
            finding = self.session.add_finding(
                severity=Severity(result.severity),
                title=f"Prompt injection ({result.category}) on LLM endpoint",
                description=(f"Payload '{result.payload_id}' delivered to {url}: {result.detail}."),
                agent=self.AGENT_NAME,
                target=url,
                evidence=[result.to_dict()],
                data=result.to_dict(),
            )
            # Only an out-of-band callback proves the injection executed;
            # everything else is a signal in the response text.
            finding.confidence = 1.0 if result.oob_confirmed else 0.6
