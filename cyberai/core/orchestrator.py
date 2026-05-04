"""
Orchestrator — coordinates the full multi-agent pipeline.
ReconAgent → IntelAgent → ExploitAgent → ReportAgent
"""
from __future__ import annotations
import time
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel

from cyberai.core.scan_session import ScanSession, ScanPhase
from cyberai.core.logger import get_logger

console = Console()
log = get_logger("orchestrator")


class Orchestrator:
    """
    Runs the full CyberAI pipeline for a given target.
    Phases are configurable — skip any by omitting from phases list.
    """

    DEFAULT_PHASES = [
        ScanPhase.RECON,
        ScanPhase.INTEL,
        ScanPhase.EXPLOIT,
        ScanPhase.REPORT,
    ]

    def __init__(
        self,
        phases: List[ScanPhase] = None,
        authorized_scope: List[str] = None,
        dry_run: bool = False,
    ):
        self.phases           = phases or self.DEFAULT_PHASES
        self.authorized_scope = authorized_scope or []
        self.dry_run          = dry_run

    def run(self, target: str) -> ScanSession:
        """
        Execute full pipeline for target.
        Returns completed ScanSession with all results in KB.
        """
        session = ScanSession(
            target=target,
            authorized_scope=self.authorized_scope,
        )

        console.print(Panel(
            f"[bold red]CyberAI Orchestrator[/bold red]\n"
            f"Target  : [yellow]{target}[/yellow]\n"
            f"Phases  : [yellow]{[p.value for p in self.phases]}[/yellow]\n"
            f"Scope   : [yellow]{self.authorized_scope or 'not set'}[/yellow]\n"
            f"Dry Run : [yellow]{self.dry_run}[/yellow]\n"
            f"Session : [dim]{session.session_id}[/dim]",
            border_style="red",
        ))

        session.start()
        log.info(f"Pipeline started — target={target} session={session.session_id}")

        for phase in self.phases:
            self._run_phase(session, phase)
            if not session.phases[-1].success:
                log.warning(f"Phase {phase.value} failed — continuing pipeline")

        if all(p.success for p in session.phases):
            session.complete()
            console.print("[bold green]✓ Pipeline complete[/bold green]")
        else:
            failed = [p.phase.value for p in session.phases if not p.success]
            session.fail(f"Failed phases: {failed}")
            console.print(f"[bold red]✗ Pipeline finished with errors: {failed}[/bold red]")

        log.info(f"Pipeline done — state={session.state.value}")
        return session

    def _run_phase(self, session: ScanSession, phase: ScanPhase) -> None:
        console.print(f"\n[bold red]▶ {phase.value.upper()}[/bold red]")
        started = _now()
        session.set_phase(phase)

        try:
            if self.dry_run:
                data = {"dry_run": True, "phase": phase.value}
            else:
                data = self._dispatch(session, phase)

            session.record_phase(phase, success=True, started=started, data=data)
            console.print(f"[green]✓ {phase.value} done[/green]")

        except Exception as exc:
            session.record_phase(
                phase, success=False, started=started, error=str(exc)
            )
            console.print(f"[red]✗ {phase.value} error: {exc}[/red]")
            log.error(f"Phase {phase.value} raised", exc_info=True)

    def _dispatch(self, session: ScanSession, phase: ScanPhase) -> Dict[str, Any]:
        if phase == ScanPhase.RECON:
            return self._run_recon(session)
        if phase == ScanPhase.INTEL:
            return self._run_intel(session)
        if phase == ScanPhase.EXPLOIT:
            return self._run_exploit(session)
        if phase == ScanPhase.REPORT:
            return self._run_report(session)
        return {}

    def _run_recon(self, session: ScanSession) -> Dict:
        from cyberai.agents.recon.agent import ReconAgent
        result = ReconAgent(kb=session.kb).run(session.target)
        session.kb_set("recon", result)
        return result

    def _run_intel(self, session: ScanSession) -> Dict:
        from cyberai.agents.intel.agent import IntelAgent
        result = IntelAgent(kb=session.kb).run(session.target)
        session.kb_set("intel", result)
        return result

    def _run_exploit(self, session: ScanSession) -> Dict:
        from cyberai.agents.exploit.agent import ExploitAgent
        from cyberai.agents.exploit.safety_validator import validate_exploit_scope

        paths = session.kb_get("intel", {}).get("ranked_cves", [])
        v = validate_exploit_scope(session.target, session.authorized_scope, paths)

        if not v.passed:
            raise RuntimeError(f"Scope check failed: {v.violations}")
        for w in v.warnings:
            console.print(f"[yellow]⚠ {w}[/yellow]")

        result = ExploitAgent(kb=session.kb).run(session.target)
        session.kb_set("exploit", result)
        return result

    def _run_report(self, session: ScanSession) -> Dict:
        from cyberai.agents.report.agent import ReportAgent
        from cyberai.agents.report.html_renderer import render_html_report

        result = ReportAgent(kb=session.kb).run(session.target)
        session.kb_set("report", result)

        output = f"report_{session.session_id}.html"
        render_html_report(session.summary(), session.kb, output_path=output)
        console.print(f"[dim]HTML report: {output}[/dim]")
        return {**result, "html_report": output}


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
