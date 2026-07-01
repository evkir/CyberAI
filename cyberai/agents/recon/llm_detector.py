"""LLM / RAG endpoint detection for reconnaissance.

Probes a target for signs of an LLM-backed service — chat/completions
APIs, RAG query endpoints, or streaming chat channels — so that discovered
endpoints can be routed into the injection fuzzer. Detection is signal-
based and never asserts a vulnerability; it only flags a candidate surface.

Network access is abstracted behind a `prober` callable so the detector is
fully testable without live traffic.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

import httpx

# Endpoint paths commonly exposed by LLM / RAG services.
_CANDIDATE_PATHS = (
    "/v1/chat/completions",
    "/v1/completions",
    "/api/chat",
    "/api/generate",  # ollama
    "/api/v1/chat",
    "/chat",
    "/rag",
    "/query",
    "/ask",
)

# Distinctive LLM-API paths where a method/auth-gated status (405/401/400)
# is itself a strong signal that the endpoint exists. Generic paths are
# excluded — too many unrelated services expose /query or /ask.
_STRONG_PATHS = frozenset(
    {
        "/v1/chat/completions",
        "/v1/completions",
        "/api/chat",
        "/api/generate",
        "/api/v1/chat",
    }
)
_GATED_STATUSES = frozenset({400, 401, 405})

# Response body keys typical of LLM API payloads.
_BODY_SIGNALS = ("choices", "completion", "model", "response", "message", "answer")

# Header hints (lowercased name → substring in value, or "" for presence).
_HEADER_SIGNALS = (
    ("content-type", "text/event-stream"),  # streaming chat
    ("x-ratelimit-limit-requests", ""),  # openai-style quota headers
    ("openai-organization", ""),
    ("anthropic-version", ""),
)

# HTML markers suggesting an embedded chat/assistant widget.
_HTML_SIGNALS = ("chatbot", "ask me anything", "chat-widget", "assistant", "send a message")

# A prober maps a URL to a simplified response dict or None on failure.
ProbeFn = Callable[[str], Optional[dict[str, Any]]]


def _default_prober(timeout: float) -> ProbeFn:
    """Return a prober that issues a lightweight GET via httpx."""

    def _probe(url: str) -> Optional[dict[str, Any]]:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                r = client.get(url)
                body: Any = ""
                ctype = r.headers.get("content-type", "")
                if "application/json" in ctype:
                    try:
                        body = r.json()
                    except Exception:
                        body = r.text[:2048]
                else:
                    body = r.text[:2048]
                return {
                    "status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body,
                }
        except Exception:
            return None

    return _probe


def _score_response(path: str, resp: dict[str, Any]) -> list[str]:
    """Collect the LLM/RAG signals present in one probe response."""
    signals: list[str] = []

    # Method/auth-gated status on a distinctive LLM path implies existence.
    status = resp.get("status")
    if path in _STRONG_PATHS and status in _GATED_STATUSES:
        signals.append(f"status:{status}-gated")

    headers = resp.get("headers", {})
    for name, needle in _HEADER_SIGNALS:
        val = headers.get(name)
        if val is not None and (needle == "" or needle in val.lower()):
            signals.append(f"header:{name}")

    body = resp.get("body", "")
    if isinstance(body, dict):
        for key in _BODY_SIGNALS:
            if key in body:
                signals.append(f"body-key:{key}")
    elif isinstance(body, str):
        low = body.lower()
        for marker in _HTML_SIGNALS:
            if marker in low:
                signals.append(f"html:{marker}")
    return signals


def _confidence(signals: list[str]) -> str:
    """Map signal count/kind to a confidence label."""
    has_api = any(s.startswith(("header:", "body-key:", "status:")) for s in signals)
    if has_api and len(signals) >= 2:
        return "high"
    if has_api or len(signals) >= 2:
        return "medium"
    return "low"


def _normalize_base(target: str) -> str:
    """Ensure the target has an http(s) scheme; default to http."""
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"http://{target}".rstrip("/")


def detect_llm_endpoints(
    target: str,
    prober: Optional[ProbeFn] = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Probe `target` for LLM/RAG endpoints and return candidate surfaces.

    `prober` maps a URL to a response dict (`status`, `headers`, `body`) or
    None; when omitted, a live httpx GET prober is used. Each candidate is
    reported with its matched signals and a confidence label. A distinctive
    LLM path answering with a method/auth-gated status counts as a signal,
    so POST-only chat APIs are not missed during passive GET reconnaissance.
    This flags a fuzzing surface only — it never asserts a vulnerability.
    """
    probe = prober or _default_prober(timeout)
    base = _normalize_base(target)
    endpoints: list[dict[str, Any]] = []
    for path in _CANDIDATE_PATHS:
        url = f"{base}{path}"
        resp = probe(url)
        if not resp:
            continue
        signals = _score_response(path, resp)
        if not signals:
            continue
        endpoints.append(
            {
                "url": url,
                "method": "GET",
                "status": resp.get("status"),
                "signals": signals,
                "confidence": _confidence(signals),
            }
        )
    return {
        "target": target,
        "llm_endpoints": endpoints,
        "is_llm_target": bool(endpoints),
    }
