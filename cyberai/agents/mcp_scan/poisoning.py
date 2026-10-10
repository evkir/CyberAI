"""Static metadata analysis for MCP tool poisoning.

MCP tool-poisoning hides adversarial instructions in the metadata an LLM reads
before it ever calls a tool: the description, the JSON-schema field
descriptions, and the free-form ``annotations`` / ``meta`` blocks. This module
flattens all of that text out of a probed tool dict and runs it through the
existing prompt-injection detector, so hidden "ignore previous instructions",
encoded payloads, and unicode smuggling surface as signals.

This stage produces a raw scan; severity scoring and MCP-specific patterns are
layered on top in the scorer.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from cyberai.core.scan_session import Severity
from cyberai.core.security.injection_detector import detect_injection

# MCP-specific poisoning patterns not covered by the generic injection detector.
# These target the tool-metadata channel directly: shadowing other tools,
# smuggled "important"/hidden directives the model is told to obey, and
# exfiltration instructions embedded in a description.
MCP_POISONING_PATTERNS: list[tuple[str, str]] = [
    (r"<\s*important\s*>", "hidden_directive"),
    (r"do not (tell|mention|inform|reveal to) (the )?(user|human)", "concealment"),
    (r"without (telling|informing|alerting) (the )?(user|human)", "concealment"),
    (r"before (using|calling|invoking) this tool", "line_jumping"),
    (r"when (using|calling) (any |the )?other tool", "tool_shadowing"),
    (r"instead of (the |calling )?\w+ tool", "tool_shadowing"),
    # Exfiltration is a verb plus a DESTINATION, and the destination is what
    # this matcher requires. The earlier form accepted the preposition as
    # optional and let "webhook" satisfy it as a bare word, so a mail server
    # advertising "send email, manage mailboxes, domains and webhooks" matched
    # on a list of its own capabilities, and an access log line reading
    # "POST / HTTP/1.1" matched on the verb standing next to the scheme.
    # Measured 10.10 over 13 525 active registry descriptions: the old form
    # fired twice, both false; this one fires zero times and still carries
    # every true case in the fixtures.
    (
        r"(send|forward|leak|exfiltrate|post)\b[^.\n]{0,60}?\bto\s+"
        r"[^.\n]{0,30}?(https?://|attacker|webhook\.|/webhook|endpoint|server)",
        "exfil_instruction",
    ),
    (r"include .{0,30}(api[_ ]?key|token|secret|password|credential)", "credential_harvest"),
    (r"read .{0,30}(\.env|id_rsa|/etc/passwd|ssh key|config file)", "sensitive_read"),
    # Icons, revision 2025-11-25. What is scored is the carrier, not the fact
    # of an external reference: a tool icon served from a CDN is ordinary, and
    # this matcher sees flattened text, so it cannot tell the server's own
    # origin from anyone else's. A pattern on "src is remote" would therefore
    # flag the normal case and measure nothing. These two describe content the
    # client executes or renders as markup while showing the tool's name --
    # before the user has agreed to call anything.
    (
        r'"src"\s*:\s*"\s*(?:javascript:|vbscript:|data:text/html|data:image/svg)',
        "icon_active_scheme",
    ),
    (
        r'"mimeType"\s*:\s*"image/svg\+xml"|"src"\s*:\s*"[^"]+\.svg(?:[?#][^"]*)?"',
        "icon_executable_carrier",
    ),
]
_MCP_COMPILED = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), label) for pat, label in MCP_POISONING_PATTERNS
]


@dataclass
class MetadataScan:
    """Raw injection-detector result for a single tool's metadata."""

    tool_name: str
    risk_score: int
    is_suspicious: bool
    matches: list[dict[str, Any]] = field(default_factory=list)
    scanned_fields: list[str] = field(default_factory=list)
    mcp_matches: list[dict[str, Any]] = field(default_factory=list)
    severity: str = Severity.INFO.value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _schema_strings(node: Any) -> list[str]:
    """Recursively collect human-readable strings from a JSON Schema fragment.

    Only ``description``/``title`` values and ``enum`` members are collected —
    these are the parts an LLM is shown and could be weaponized.
    """
    out: list[str] = []
    if isinstance(node, dict):
        for key, val in node.items():
            if key in ("description", "title") and isinstance(val, str):
                out.append(val)
            elif key == "enum" and isinstance(val, list):
                out.extend(str(v) for v in val)
            else:
                out.extend(_schema_strings(val))
    elif isinstance(node, list):
        for item in node:
            out.extend(_schema_strings(item))
    return out


# The tool metadata an LLM is shown that is not plain text: each is dumped
# whole rather than walked, because a directive can sit in any value. The
# over-privilege stage reads the same list -- it was blind to three of these
# until measured, and a tool hiding "send the result to <url>" in _meta or
# outputSchema scored an empty capability surface while poisoning flagged it.
SERVER_CONTROLLED_BLOBS: tuple[str, ...] = ("annotations", "_meta", "outputSchema", "icons")


def _collect_text(tool: dict[str, Any]) -> tuple[str, list[str]]:
    """Flatten all LLM-visible metadata of a tool into one scannable blob."""
    parts: list[str] = []
    fields: list[str] = []
    for key in ("name", "title", "description"):
        val = tool.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
            fields.append(key)
    schema_strings = _schema_strings(tool.get("inputSchema") or {})
    if schema_strings:
        parts.extend(schema_strings)
        fields.append("inputSchema")
    # `icons` arrived with revision 2025-11-25 and is server-controlled text
    # that reaches the client before any call: `src` is a URL the client is
    # expected to fetch, and `mimeType`/`sizes` are free strings rendered next
    # to the tool's name. The whitelist above named seven keys and this was not
    # one of them, so a directive carried in an icon field reached no matcher
    # at all -- not because no pattern described it, but because the text was
    # never collected. A channel nothing reads cannot be scored.
    # ``_meta`` is the protocol spelling and the probe dumps by alias. This
    # loop once asked for "meta", so a directive a server put there reached
    # no matcher and the tool scored clean.
    for key in SERVER_CONTROLLED_BLOBS:
        val = tool.get(key)
        if val:
            parts.append(json.dumps(val, default=str))
            fields.append(key)
    return "\n".join(parts), fields


def _scan_mcp_patterns(text: str) -> list[dict[str, Any]]:
    """Match MCP-specific poisoning patterns the generic detector misses."""
    out: list[dict[str, Any]] = []
    for pattern, label in _MCP_COMPILED:
        found = pattern.findall(text)
        if found:
            out.append({"type": label, "pattern": pattern.pattern})
    return out


def _severity_for(risk_score: int, mcp_matches: list[dict[str, Any]]) -> Severity:
    """Map combined signals to a severity tier.

    MCP-specific hits (concealment, exfil, tool-shadowing) are a stronger
    signal than generic prompt-injection text and raise the floor.
    """
    mcp_labels = {m["type"] for m in mcp_matches}
    if mcp_labels & {"exfil_instruction", "credential_harvest", "sensitive_read", "concealment"}:
        return Severity.CRITICAL
    if mcp_labels:
        return Severity.HIGH
    if risk_score >= 75:
        return Severity.HIGH
    if risk_score >= 50:
        return Severity.MEDIUM
    if risk_score >= 25:
        return Severity.LOW
    return Severity.INFO


def analyze_tool(tool: dict[str, Any]) -> MetadataScan:
    """Scan one probed tool dict for poisoning signals in its metadata."""
    text, scanned_fields = _collect_text(tool)
    result = detect_injection(text)
    mcp_matches = _scan_mcp_patterns(text)
    severity = _severity_for(result["risk_score"], mcp_matches)
    return MetadataScan(
        tool_name=tool.get("name", "<unnamed>"),
        risk_score=result["risk_score"],
        is_suspicious=result["is_injection"] or bool(mcp_matches),
        matches=result["matches"],
        scanned_fields=scanned_fields,
        mcp_matches=mcp_matches,
        severity=severity.value,
    )


def analyze_tools(tools: list[dict[str, Any]]) -> list[MetadataScan]:
    """Scan every tool in a probe inventory."""
    return [analyze_tool(tool) for tool in tools]
