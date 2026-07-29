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


def _default_channel(url: str, timeout: float = DEFAULT_TIMEOUT) -> Callable[[str], str]:
    """Return a send function that POSTs a payload to `url` as JSON."""

    def _send(payload: str) -> str:
        body = {field: payload for field in _PROMPT_FIELDS}
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                return client.post(url, json=body).text
        except Exception:
            return ""

    return _send


class RedTeamAgent(BaseAgent):
    """Fuzz the LLM channels a plan names; record confirmed injections."""

    AGENT_NAME = "redteam"
    ROLE = "LLM Red Team"

    def _register_tools(self) -> None:  # channels are driven directly
        pass

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._check_iteration_limit()
        urls = self._planned_channels()
        if not urls:
            self._log("No injection-fuzz subtasks in plan — red team skipped")
            return {"channels": 0, "confirmed": 0, "reports": []}

        fuzzer = (context or {}).get("fuzzer") or LLMChannelFuzzer()
        channel_factory = (context or {}).get("channel_factory") or _default_channel

        reports: List[Dict[str, Any]] = []
        confirmed = 0
        for url in urls:
            report = fuzzer.fuzz_channel(channel_factory(url), channel_id=url)
            confirmed += report.confirmed_count
            self._record(report, url)
            reports.append(report.to_dict())

        self.kb.set("redteam.reports", reports, agent=self.AGENT_NAME)
        self._log(f"fuzzed {len(urls)} channel(s), {confirmed} confirmed")
        return {"channels": len(urls), "confirmed": confirmed, "reports": reports}

    def _planned_channels(self) -> List[str]:
        """URLs from injection-fuzz subtasks, in plan order, deduplicated."""
        plan = self.kb.get("plan") or {}
        todo = plan.get("todo") if isinstance(plan, dict) else None
        if not isinstance(todo, list):
            return []
        urls: List[str] = []
        for task in todo:
            if not isinstance(task, dict) or task.get("action") != "injection-fuzz":
                continue
            url = task.get("target")
            if url and url not in urls:
                urls.append(str(url))
        return urls

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
