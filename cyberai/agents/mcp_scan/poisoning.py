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
from dataclasses import asdict, dataclass, field
from typing import Any

from cyberai.core.security.injection_detector import detect_injection


@dataclass
class MetadataScan:
    """Raw injection-detector result for a single tool's metadata."""

    tool_name: str
    risk_score: int
    is_suspicious: bool
    matches: list[dict[str, Any]] = field(default_factory=list)
    scanned_fields: list[str] = field(default_factory=list)

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
    for key in ("annotations", "meta", "outputSchema"):
        val = tool.get(key)
        if val:
            parts.append(json.dumps(val, default=str))
            fields.append(key)
    return "\n".join(parts), fields


def analyze_tool(tool: dict[str, Any]) -> MetadataScan:
    """Scan one probed tool dict for injection signals in its metadata."""
    text, scanned_fields = _collect_text(tool)
    result = detect_injection(text)
    return MetadataScan(
        tool_name=tool.get("name", "<unnamed>"),
        risk_score=result["risk_score"],
        is_suspicious=result["is_injection"],
        matches=result["matches"],
        scanned_fields=scanned_fields,
    )


def analyze_tools(tools: list[dict[str, Any]]) -> list[MetadataScan]:
    """Scan every tool in a probe inventory."""
    return [analyze_tool(tool) for tool in tools]
