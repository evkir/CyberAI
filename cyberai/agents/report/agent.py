"""ReportAgent — renders Markdown + JSON reports from the session."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import json

from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.llm_usage import llm_usage_record
from cyberai.core.types import ReportSection

from .json_exporter import export_json
from .judge import judge_report
from .markdown_renderer import render_markdown


class ReportAgent(BaseAgent):
    """Report generation agent — renders Markdown + JSON, saves to disk."""

    AGENT_NAME = "report"
    ROLE = "Report Writer"

    def _register_tools(self) -> None:
        self.register_tool(
            Tool(
                name="render_markdown",
                description="Render Markdown pentest report",
                func=render_markdown,
                parameters={"session": "ScanSession"},
            )
        )
        self.register_tool(
            Tool(
                name="export_json",
                description="Export session as JSON report",
                func=export_json,
                parameters={"session": "ScanSession", "output_dir": "str"},
            )
        )

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

        # Flag-gated: LLM-generated structured executive section.
        if self.config.use_llm_summary and self.llm is not None:
            section = self._structured_summary(target)
            if section is not None:
                self.kb.set("report.section", section.model_dump(), agent=self.AGENT_NAME)
                # Written before the judge runs, so the judge scores the same
                # document the operator receives rather than an earlier draft.
                md_content = self._append_section(md_content, section)
                with open(md_path, "w") as f:
                    f.write(md_content)

        # Flag-gated: LLM-as-Judge cross-checks the report against KB evidence.
        verdict_dump = None
        if self.config.use_judge and self.llm is not None:
            verdict = judge_report(
                md_content,
                self.session,
                self.llm,
                threshold=self.config.judge_threshold,
                judge_model=self.config.judge_model,
            )
            verdict_dump = verdict.model_dump()
            self.kb.set("report.judge_verdict", verdict_dump, agent=self.AGENT_NAME)
            md_content = self._append_verdict(md_content, verdict)
            with open(md_path, "w") as f:
                f.write(md_content)
            self._log(
                f"Judge: score={verdict.hallucination_score:.2f} supported={verdict.supported}"
            )

        # Last, because the summary and the judge above are themselves model
        # calls: recording earlier would report a number the reader can see is
        # wrong. JSON is re-exported for the same reason -- it was written
        # before either of them ran.
        usage = self._record_llm_usage()
        if usage is not None:
            md_content = self._append_llm_usage(md_content, usage)
            with open(md_path, "w") as f:
                f.write(md_content)
            json_path = export_json(self.session, output_dir)
            self.kb.set("report.json_path", json_path, agent=self.AGENT_NAME)

        result = {
            "status": "done",
            "markdown": md_path,
            "json": json_path,
            "total_findings": len(self.session.findings),
        }
        if verdict_dump is not None:
            result["judge_verdict"] = verdict_dump
        return result

    def _record_llm_usage(self) -> dict | None:
        """Write llm.usage before the documents are closed, and return it.

        The orchestrator writes the same key after every phase has finished,
        which is after this agent has already saved its files: the report
        carried an empty key while the session dump carried the numbers. The
        shape comes from core/llm_usage so the two writers cannot disagree.
        """
        tracker = getattr(self.llm, "cost_tracker", None)
        if tracker is None:
            return None
        record = llm_usage_record(self.config.llm, tracker, client_built=self.llm is not None)
        self.kb.set("llm.usage", record, agent=self.AGENT_NAME)
        return record

    def _append_llm_usage(self, md: str, record: dict) -> str:
        """Append what the model did, including nothing and why.

        Written like the section and the verdict above rather than re-rendered:
        the document at this point already carries both, and rebuilding it from
        the session would drop them.
        """
        lines = [
            md,
            "",
            "---",
            "",
            "## Model Participation",
            "",
            f"**Provider:** {record.get('provider', '')}  ",
            f"**Model:** `{record.get('model', '')}`  ",
            f"**Calls answered:** {record.get('calls', 0)}  ",
            f"**Calls attempted:** {record.get('attempts', 0)}",
        ]
        reason = record.get("zero_reason")
        if reason:
            lines += ["", f"No model output reached this report: `{reason}`."]
        agents = record.get("by_agent") or []
        if agents:
            lines += ["", "Asked by: " + ", ".join(f"`{a}`" for a in agents)]
        tokens_in = record.get("input_tokens", 0)
        tokens_out = record.get("output_tokens", 0)
        if tokens_in or tokens_out:
            lines += ["", f"Tokens: {tokens_in:,} in / {tokens_out:,} out"]
        lines.append("")
        return "\n".join(lines)

    def _append_section(self, md: str, section: ReportSection) -> str:
        """Append the LLM executive section as Markdown.

        Without this the section was written to the knowledge base and
        nowhere else: the call was paid for, the tokens were spent, and the
        document the operator opens never showed it.
        """
        lines = [
            md,
            "",
            "---",
            "",
            "## 🤖 Executive Section (LLM)",
            "",
            f"**{section.title}**  ",
            f"**Severity:** {section.severity}  ",
        ]
        if section.impact:
            lines.append("")
            lines.append(f"**Impact:** {section.impact}")
        if section.findings:
            lines.append("")
            lines.append("**Key findings:**")
            lines.append("")
            for item in section.findings:
                lines.append(f"- {item}")
        if section.recommendations:
            lines.append("")
            lines.append("**Recommendations:**")
            lines.append("")
            for item in section.recommendations:
                lines.append(f"- {item}")
        lines.append("")
        return "\n".join(lines)

    def _append_verdict(self, md: str, verdict) -> str:
        """Append the judge verdict as a Markdown section to the report."""
        status = "✅ SUPPORTED" if verdict.supported else "⚠️ UNSUPPORTED"
        lines = [
            md,
            "",
            "---",
            "",
            "## 🧑‍⚖️ Report Validation (LLM-as-Judge)",
            "",
            f"**Status:** {status}  ",
            f"**Hallucination score:** {verdict.hallucination_score:.2f}  ",
        ]
        if verdict.unsupported_claims:
            lines.append("")
            lines.append("**Unsupported claims:**")
            lines.append("")
            for claim in verdict.unsupported_claims:
                lines.append(f"- {claim}")
        if verdict.notes:
            lines.append("")
            lines.append(f"_Notes: {verdict.notes}_")
        lines.append("")
        return "\n".join(lines)

    def _structured_summary(self, target: str):
        """Flag-gated: ask the LLM for a Pydantic-validated ReportSection.

        Uses LLMClient.structured_call with ReportSection's JSON Schema; the
        provider returns JSON, which we validate. Returns None on any failure
        so the deterministic report is never blocked.
        """
        if self.llm is None:
            return None
        findings = [
            {
                "title": f.title,
                "severity": getattr(f.severity, "value", str(f.severity)),
                "description": f.description,
            }
            for f in self.session.findings
        ]
        system = (
            "You are a penetration-test report writer. Summarize the findings "
            "into one executive ReportSection: a concise title, the highest "
            "applicable severity, key findings, concrete recommendations, and "
            "a short business impact statement."
        )
        messages = [
            {
                "role": "user",
                "content": (f"Target: {target}\nFindings JSON:\n{json.dumps(findings, indent=2)}"),
            }
        ]
        schema = ReportSection.model_json_schema()
        try:
            raw = self.llm.structured_call(
                messages,
                schema=schema,
                schema_name="report_section",
                description="Executive pentest report section.",
                system=system,
                agent_name=self.AGENT_NAME,
            )
            return ReportSection.model_validate(raw)
        except Exception as exc:  # noqa: BLE001 — report must never hard-fail
            self._log(f"LLM structured summary failed: {exc}")
            return None
