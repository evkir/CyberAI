"""Static over-privilege analysis for MCP tools.

A poisoned description steers the model; an over-privileged tool gives it the
reach to act. This module maps the *capability surface* a tool exposes —
filesystem, network, process execution, credential access, database — purely
from the metadata an MCP server advertises (name, description, JSON-schema
parameter names and descriptions, annotations).

This stage only detects which capability classes a tool touches. Scoring of
dangerous combinations (e.g. filesystem-read paired with network egress) is
layered on top in the heuristics stage.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from cyberai.core.scan_session import Severity

# Capability-class signals keyed by class. Matched against a normalized,
# lower-cased projection of the tool metadata where every non-alphanumeric run
# is collapsed to a single space, so word boundaries behave across
# snake_case / kebab-case (``read_file`` -> ``read file``) while substrings
# like ``download`` do not falsely trip ``\bload\b``.
CAPABILITY_SIGNALS: dict[str, list[str]] = {
    "fs_read": [
        r"\bread\b",
        r"\bopen\b",
        r"\bcat\b",
        r"\bload\b",
        r"\bfile\b",
        r"\bfiles\b",
        r"\bpath\b",
        r"\bcontent\b",
        r"\bcontents\b",
        r"\bdirectory\b",
        r"\bdir\b",
    ],
    "fs_write": [
        r"\bwrite\b",
        r"\bsave\b",
        r"\bdelete\b",
        r"\bremove\b",
        r"\bunlink\b",
        r"\bmodify\b",
        r"\bappend\b",
        r"\boverwrite\b",
        r"\bmkdir\b",
    ],
    "net": [
        r"\bhttp\b",
        r"\bhttps\b",
        r"\burl\b",
        r"\bfetch\b",
        r"\brequest\b",
        r"\bdownload\b",
        r"\bupload\b",
        r"\bsend\b",
        r"\bpost\b",
        r"\bwebhook\b",
        r"\bendpoint\b",
        r"\bsocket\b",
    ],
    "exec": [
        r"\bexec\b",
        r"\brun\b",
        r"\bshell\b",
        r"\bcommand\b",
        r"\bcmd\b",
        r"\beval\b",
        r"\bsubprocess\b",
        r"\bspawn\b",
        r"\bsystem\b",
        r"\bbash\b",
        r"\bpowershell\b",
        r"\bscript\b",
    ],
    "cred": [
        r"\benv\b",
        r"\benvironment\b",
        r"\bsecret\b",
        r"\btoken\b",
        r"\bapi key\b",
        r"\bapikey\b",
        r"\bpassword\b",
        r"\bcredential\b",
        r"\bprivate key\b",
        r"\bid rsa\b",
    ],
    "db": [
        r"\bsql\b",
        r"\bquery\b",
        r"\bdatabase\b",
        r"\bdb\b",
        r"\bselect\b",
        r"\binsert\b",
        r"\bmongo\b",
        r"\bpostgres\b",
        r"\bmysql\b",
    ],
}
_COMPILED_SIGNALS: dict[str, list[re.Pattern[str]]] = {
    cap: [re.compile(pat) for pat in pats] for cap, pats in CAPABILITY_SIGNALS.items()
}


@dataclass
class CapabilitySurface:
    """Capability classes a single tool exposes, inferred from its metadata."""

    tool_name: str
    capabilities: list[str] = field(default_factory=list)
    signals: dict[str, list[str]] = field(default_factory=dict)
    scanned_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _schema_strings(node: Any) -> list[str]:
    """Collect capability-relevant strings from a JSON schema subtree.

    Parameter *names* (``properties`` keys) are strong capability signals
    (``command``, ``file_path``, ``url``), so they are harvested alongside any
    ``description``/``title`` text and string ``enum`` values.
    """
    out: list[str] = []
    if isinstance(node, dict):
        for key, val in node.items():
            if key == "properties" and isinstance(val, dict):
                out.extend(str(name) for name in val)
            if key in ("description", "title") and isinstance(val, str):
                out.append(val)
            if key == "enum" and isinstance(val, list):
                out.extend(str(v) for v in val if isinstance(v, str))
            out.extend(_schema_strings(val))
    elif isinstance(node, list):
        for item in node:
            out.extend(_schema_strings(item))
    return out


def _collect_capability_text(tool: dict[str, Any]) -> tuple[str, list[str]]:
    """Project tool metadata into a normalized text blob plus scanned fields."""
    parts: list[str] = []
    fields: list[str] = []
    for key in ("name", "title", "description"):
        val = tool.get(key)
        if isinstance(val, str) and val:
            parts.append(val)
            fields.append(key)
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        schema_text = _schema_strings(schema)
        if schema_text:
            parts.extend(schema_text)
            fields.append("inputSchema")
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and annotations:
        parts.append(json.dumps(annotations))
        fields.append("annotations")
    raw = " ".join(parts).lower()
    norm = re.sub(r"[^a-z0-9]+", " ", raw)
    return norm, fields


def _detect(text: str) -> dict[str, list[str]]:
    """Return capability class -> sorted unique matched terms found in text."""
    found: dict[str, list[str]] = {}
    for cap, patterns in _COMPILED_SIGNALS.items():
        hits: list[str] = []
        for pat in patterns:
            match = pat.search(text)
            if match:
                hits.append(match.group(0))
        if hits:
            found[cap] = sorted(set(hits))
    return found


def map_capability_surface(tool: dict[str, Any]) -> CapabilitySurface:
    """Infer the capability surface of a single probed tool dict."""
    text, fields = _collect_capability_text(tool)
    signals = _detect(text)
    return CapabilitySurface(
        tool_name=tool.get("name", "<unknown>"),
        capabilities=sorted(signals),
        signals=signals,
        scanned_fields=fields,
    )


def map_capability_surfaces(tools: list[dict[str, Any]]) -> list[CapabilitySurface]:
    """Map the capability surface of every tool in a probe inventory."""
    return [map_capability_surface(tool) for tool in tools]


# Severity ranking so the scorer can take the max across matched rules.
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_IO_CLASSES = {"net", "fs_read", "fs_write", "cred", "db"}


@dataclass
class OverPrivScan:
    """Over-privilege assessment of a single tool's capability surface."""

    tool_name: str
    capabilities: list[str] = field(default_factory=list)
    severity: str = Severity.INFO.value
    reasons: list[str] = field(default_factory=list)
    surface: dict[str, Any] = field(default_factory=dict)

    @property
    def is_overprivileged(self) -> bool:
        return _SEVERITY_RANK[Severity(self.severity)] >= _SEVERITY_RANK[Severity.MEDIUM]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_overprivileged"] = self.is_overprivileged
        return data


def score_overprivilege(surface: CapabilitySurface) -> OverPrivScan:
    """Score a capability surface for dangerous over-privileged combinations.

    The score is the maximum severity across all matched rules — a tool is as
    dangerous as its worst capability combination, not the sum. This is a
    static inference from declared metadata, not a runtime proof of access.
    """
    caps = set(surface.capabilities)
    rules: list[tuple[Severity, str]] = []

    has_exec = "exec" in caps
    exec_io = caps & _IO_CLASSES
    if has_exec and exec_io:
        rules.append(
            (
                Severity.CRITICAL,
                f"exec capability paired with {', '.join(sorted(exec_io))} "
                "forms a full command-and-I/O primitive",
            )
        )
    if "cred" in caps and "net" in caps:
        rules.append(
            (
                Severity.CRITICAL,
                "credential access paired with network egress is a direct exfil channel",
            )
        )
    if "fs_read" in caps and "net" in caps:
        rules.append(
            (Severity.HIGH, "filesystem read paired with network egress enables data exfiltration")
        )
    if "fs_write" in caps and "net" in caps:
        rules.append(
            (
                Severity.HIGH,
                "filesystem write paired with network egress enables remote drop / backdoor",
            )
        )
    if "db" in caps and "net" in caps:
        rules.append(
            (
                Severity.HIGH,
                "database access paired with network egress enables data dump exfiltration",
            )
        )
    if has_exec and not exec_io:
        rules.append((Severity.HIGH, "process-execution capability is high-risk on its own"))
    if "cred" in caps and "net" not in caps:
        rules.append(
            (Severity.MEDIUM, "credential access declared without an obvious egress channel")
        )
    if len(caps) >= 3:
        rules.append(
            (
                Severity.MEDIUM,
                f"broad capability surface ({', '.join(sorted(caps))}) violates least privilege",
            )
        )

    if rules:
        worst = max(rules, key=lambda r: _SEVERITY_RANK[r[0]])
        severity = worst[0]
        reasons = [reason for sev, reason in rules]
    else:
        severity = Severity.LOW if caps else Severity.INFO
        reasons = []

    return OverPrivScan(
        tool_name=surface.tool_name,
        capabilities=surface.capabilities,
        severity=severity.value,
        reasons=reasons,
        surface=surface.to_dict(),
    )


def analyze_overprivilege(tools: list[dict[str, Any]]) -> list[OverPrivScan]:
    """Map and score the over-privilege risk of every tool in an inventory."""
    return [score_overprivilege(map_capability_surface(tool)) for tool in tools]
