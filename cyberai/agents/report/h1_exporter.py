"""HackerOne-compatible Markdown export for a ReportSection (day 20)."""

from __future__ import annotations

from cyberai.core.types import ReportSection

# Map internal severity to HackerOne's severity vocabulary.
_H1_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "None",
}


def _bullets(items: list[str]) -> str:
    """Render a list as Markdown bullets; placeholder if empty."""
    if not items:
        return "_None provided._"
    return "\n".join(f"- {it}" for it in items)


def export_hackerone(section: ReportSection) -> str:
    """Render a ReportSection as a HackerOne-style Markdown submission.

    Sections follow the H1 report template: Title, Severity, Steps to
    Reproduce, Impact, Recommendation. `findings` map to reproduction
    steps; `recommendations` to the Recommendation block.
    """
    severity = _H1_SEVERITY.get(section.severity.upper(), "None")
    impact = section.impact.strip() or "_Impact not specified._"
    return (
        f"# {section.title}\n\n"
        f"**Severity:** {severity}\n\n"
        f"## Steps to Reproduce\n\n"
        f"{_bullets(section.findings)}\n\n"
        f"## Impact\n\n"
        f"{impact}\n\n"
        f"## Recommendation\n\n"
        f"{_bullets(section.recommendations)}\n"
    )
