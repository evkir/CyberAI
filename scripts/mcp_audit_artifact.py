#!/usr/bin/env python3
"""Run the MCP scanner against this repository's own servers and write the card.

Why a script and not a test. The scan starts real processes and speaks a real
stdio handshake to each of them; that is seconds per target and two child
interpreters, which is the reason bench cards are not produced inside the
suite either. What the suite does instead is check the committed card against
the tree, so a card that stopped matching the scanner is caught without
re-running it.

Why it does not extend build_mcp_report. That renderer is pure and
deterministic -- the same result renders to the same bytes, which is what lets
a test compare a committed card to a fresh render. A timestamp or a tool
version inside it would end that property. Provenance therefore lives here,
around the render, exactly as RunMeta lives around the bench renderer.

Why two targets and not one. A card produced from a stand we built for our own
scanner answers "does the agent do what we planned", not "does it find
anything unplanned" -- the cost named in the card itself. The second target is
this project's own MCP server, which nobody wrote as a test case, and it is
the control: if the scanner painted everything, both cards would look alike.

Why llm_calls is zero rather than absent. Measured on this path: the scan
agent holds an LLMClient and calls it nowhere (no reference to it anywhere in
agents/mcp_scan/), and the classifier layer is off unless CYBERAI_DETECTOR_L2
names it. Zero here means a model was proven not to have been reached, which
is what makes these figures reproducible without a GPU.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import pathlib
import sys
from typing import Any

from cyberai.agents.mcp_scan import MCPScanAgent
from cyberai.agents.mcp_scan.report import build_mcp_report
from cyberai.core.config import CyberAIConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.logger import AuditLogger
from cyberai.core.scan_session import ScanSession
from cyberai.version import __version__

TARGETS = [
    (
        "the fixture that carries server instructions",
        "python3 tests/fixtures/mcp_instructions_server.py",
    ),
    ("this project's own MCP server", "python3 -m cyberai.mcp.server"),
]


def _why(result: dict[str, Any]) -> list[str]:
    """Name what earned a flag, from the result rather than from prose.

    The renderer prints the stage and the tool it flagged. That is enough to
    find the finding and not enough to judge it: the reader cannot see which
    words in the metadata were read, or what rule turned them into a severity.
    A card showing a CRITICAL against this project's own server has to carry
    the evidence for it, or it is an assertion about ourselves.
    """
    lines: list[str] = []
    for tool in result.get("overprivilege", {}).get("tools", []):
        surface = tool.get("surface", {})
        signals = surface.get("signals", {})
        read = "; ".join(
            f"{name} from " + ", ".join(f"`{word}`" for word in words)
            for name, words in sorted(signals.items())
        )
        reasons = " ".join(reason.rstrip(".") + "." for reason in tool.get("reasons", []))
        lines.append(
            f"- `{tool.get('tool_name')}` -- {tool.get('severity')}, "
            f"capabilities {', '.join(tool.get('capabilities', []))}. "
            f"{reasons} "
            f"Read from {', '.join(surface.get('scanned_fields', []))}: {read}."
        )
    return lines


def _demote(markdown: str) -> str:
    """Push the embedded report a level down so the card has one top heading."""
    out = ["#" + line if line.startswith("# ") else line for line in markdown.splitlines()]
    return "\n".join(out)


def _scan(endpoint: str) -> dict[str, Any]:
    config = CyberAIConfig.from_env()
    session = ScanSession(target=endpoint)
    llm = LLMClient(config.llm)
    audit = AuditLogger(session.session_id, output_dir=config.output_dir)
    return MCPScanAgent(config, session, llm, audit).run(endpoint)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()

    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = [
        "# MCP Audit Card - CyberAI's own servers",
        "",
        "| field | value |",
        "| --- | --- |",
        f"| timestamp | {stamp} |",
        f"| engine version | CyberAI {__version__} |",
        "| llm calls | 0 |",
        "| llm zero reason | the scan agent calls no model |",
        "| transport | stdio |",
        "",
    ]
    for description, endpoint in TARGETS:
        result = _scan(endpoint)
        markdown, _ = build_mcp_report(result)
        out.append(f"## Target: {description}")
        out.append("")
        out.append(f'```\npython3 -m cyberai mcp-scan "{endpoint}" --report\n```')
        out.append("")
        why = _why(result)
        if why:
            out.append("What earned the flag:")
            out.append("")
            out.extend(why)
            out.append("")
        out.append(_demote(markdown))
        out.append("")
        out.append("---")
        out.append("")

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text("\n".join(out), encoding="utf-8")
    print(f"written {args.destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
