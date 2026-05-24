"""ReportAgent — renders Markdown + JSON reports from the session."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cyberai.core.base_agent import BaseAgent, Tool

from .json_exporter import export_json
from .markdown_renderer import render_markdown


class ReportAgent(BaseAgent):
    """Report generation agent — renders Markdown + JSON, saves to disk."""

    AGENT_NAME = "report"
    ROLE = "Report Writer"

    def _register_tools(self) -> None:
        self.register_tool(Tool(
            name="render_markdown",
            description="Render Markdown pentest report",
            func=render_markdown,
            parameters={"session": "ScanSession"},
        ))
        self.register_tool(Tool(
            name="export_json",
            description="Export session as JSON report",
            func=export_json,
            parameters={"session": "ScanSession", "output_dir": "str"},
        ))

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        output_dir = str(self.config.output_dir)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # 1. Markdown
        self._check_iteration_limit()
        md_content = render_markdown(self.session)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = self.session.target.replace(":", "_").replace("/", "_")
        md_path = f"{output_dir}/report_{safe_target}_{ts}.md"
        with open(md_path, "w") as f:
            f.write(md_content)
        self._log(f"Markdown saved: {md_path}")

        # 2. JSON
        self._check_iteration_limit()
        json_path = export_json(self.session, output_dir)
        self._log(f"JSON saved: {json_path}")

        self.kb.set("report.markdown_path", md_path, agent=self.AGENT_NAME)
        self.kb.set("report.json_path", json_path, agent=self.AGENT_NAME)

        return {
            "status": "done",
            "markdown": md_path,
            "json": json_path,
            "total_findings": len(self.session.findings),
        }
