"""
Orchestrator — coordinates the full multi-agent pipeline.
ReconAgent → IntelAgent → ExploitAgent → ReportAgent

Closes the agent-construction contract (KI-1).

The orchestrator now takes a CyberAIConfig, builds the shared LLMClient
and AuditLogger, and constructs every agent with the new BaseAgent
contract: Agent(config, session, llm, audit).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel

from cyberai.core.config import CyberAIConfig
from cyberai.core.logger import AuditLogger, get_logger
from cyberai.core.scan_session import ScanPhase, ScanSession

console = Console()
log = get_logger("orchestrator")


class Orchestrator:
    """
    Runs the full CyberAI pipeline for a given target.
    Phases are configurable — skip any by omitting from the phases list.
    """

    DEFAULT_PHASES = [
        ScanPhase.RECON,
        ScanPhase.INTEL,
        ScanPhase.EXPLOIT,
        ScanPhase.REPORT,
    ]

    def __init__(
        self,
        config: Optional[CyberAIConfig] = None,
        phases: Optional[List[ScanPhase]] = None,
        dry_run: bool = False,
    ) -> None:
        self.config = config or CyberAIConfig()
        self.phases = phases or self.DEFAULT_PHASES
        self.dry_run = dry_run

        # Shared LLM client — built lazily so dry-run never needs an API key.
        self._llm = None

        # Cost tracker collects per-call token usage; CLI prints summary post-run.
        from cyberai.core.cost_tracker import CostTracker

        self.cost_tracker = CostTracker()

        # Lazy per-phase model router; built on first phase that needs the LLM.
        self._router = None

    # ── llm (lazy) ────────────────────────────────────────────────────

    @property
    def llm(self):
        """Lazily build the shared LLMClient. Skipped entirely in dry-run."""
        if self._llm is None and not self.dry_run:
            from cyberai.core.llm_client import LLMClient

            self._llm = LLMClient(
                self.config.llm,
                cost_tracker=self.cost_tracker,
                budget_usd=self.config.max_cost_usd,
            )
        return self._llm

    def _client_for(self, phase: ScanPhase):
        """Phase-appropriate LLM client. Falls back to the shared client when
        routing is disabled (default) — no behavioural change."""
        if self.dry_run:
            return self.llm
        if not self.config.routing.enable_model_routing:
            return self.llm
        if self._router is None:
            from cyberai.core.model_router import ModelRouter

            self._router = ModelRouter(
                self.config.llm,
                self.config.routing,
                cost_tracker=self.cost_tracker,
                budget_usd=self.config.max_cost_usd,
                air_gapped=self.config.air_gapped,
            )
        return self._router.client_for(phase)

    # ── public API ────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        authorized_scope: Optional[List[str]] = None,
    ) -> ScanSession:
        """
        Execute the full pipeline for `target`.
        Returns the completed ScanSession with all results in its KB.
        """
        session = ScanSession(
            target=target,
            authorized_scope=authorized_scope or [],
        )

        console.print(
            Panel(
                f"[bold red]CyberAI Orchestrator[/bold red]\n"
                f"Target  : [yellow]{target}[/yellow]\n"
                f"Phases  : [yellow]{[p.value for p in self.phases]}[/yellow]\n"
                f"Scope   : [yellow]{session.authorized_scope or 'not set'}[/yellow]\n"
                f"Dry Run : [yellow]{self.dry_run}[/yellow]\n"
                f"Session : [dim]{session.session_id}[/dim]",
                border_style="red",
            )
        )

        session.start()
        log.info(f"Pipeline started — target={target} session={session.session_id}")

        self.audit = AuditLogger(session_id=session.session_id)

        for phase in self.phases:
            self._run_phase(session, phase)
            if session.phases and not session.phases[-1].success:
                if getattr(self.config, "enable_replan", False):
                    self._maybe_replan(session, phase)
                if session.phases and not session.phases[-1].success:
                    log.warning(f"Phase {phase.value} failed — continuing pipeline")

        if session.phases and all(p.success for p in session.phases):
            session.complete()
            console.print("[bold green]✓ Pipeline complete[/bold green]")
        else:
            failed = [p.phase.value for p in session.phases if not p.success]
            session.fail(f"Failed phases: {failed}")
            console.print(f"[bold red]✗ Pipeline finished with errors: {failed}[/bold red]")

        log.info(f"Pipeline done — state={session.state.value}")
        return session

    # ── phase execution ───────────────────────────────────────────────

    def _run_phase(self, session: ScanSession, phase: ScanPhase) -> None:
        console.print(f"\n[bold red]▶ {phase.value.upper()}[/bold red]")
        started = _now()
        session.set_phase(phase)

        try:
            if self.dry_run:
                data = {"dry_run": True, "phase": phase.value}
            else:
                data = self._dispatch(session, phase)
                self._check_phase_injection(session, phase, data)

            session.record_phase(phase, success=True, started=started, data=data)
            console.print(f"[green]✓ {phase.value} done[/green]")

        except Exception as exc:  # noqa: BLE001 — pipeline must survive one bad phase
            session.record_phase(phase, success=False, started=started, error=str(exc))
            console.print(f"[red]✗ {phase.value} error: {exc}[/red]")
            log.error(f"Phase {phase.value} raised", exc_info=True)

    def _maybe_replan(self, session: ScanSession, phase: ScanPhase) -> None:
        """Ask the critic whether a just-failed phase is worth one retry."""
        from cyberai.agents.planner.critic import CriticAgent

        attempts = sum(1 for p in session.phases if p.phase == phase)
        if attempts > 1:  # already retried once — do not loop
            return
        error = session.phases[-1].error
        critic = CriticAgent(self.config, session, None, self.audit)
        verdict = critic.run(session.target, context={"phase": phase.value, "error": error})
        if verdict.get("decision") == "retry":
            console.print(f"[yellow]\u21bb critic: re-running {phase.value}[/yellow]")
            failed_idx = len(session.phases) - 1
            self._run_phase(session, phase)
            if session.phases[-1].success:
                # Drop the earlier failed attempt so the phase counts as passed.
                session.phases.pop(failed_idx)

    def _check_phase_injection(
        self, session: "ScanSession", phase: "ScanPhase", data: Dict[str, Any]
    ) -> None:
        """Scan a phase's output for prompt-injection before it propagates."""
        import json as _json

        from cyberai.core.scan_session import Severity
        from cyberai.core.security.injection_detector import detect_injection

        text = _json.dumps(data, default=str)
        result = detect_injection(text)
        if not result["is_injection"]:
            return

        console.print(
            f"[bold yellow]\u26a0 injection signals in {phase.value} "
            f"output (risk={result['risk_score']})[/bold yellow]"
        )
        session.add_finding(
            severity=Severity.MEDIUM,
            title=f"Prompt-injection signals in {phase.value} output",
            description=(
                f"Phase output matched {len(result['matches'])} injection "
                f"pattern(s); risk score {result['risk_score']}/100. Output "
                f"is treated as untrusted before reaching the LLM."
            ),
            agent="orchestrator",
            target=session.target,
            evidence=[m["type"] for m in result["matches"]],
        )

    def _dispatch(self, session: ScanSession, phase: ScanPhase) -> Dict[str, Any]:
        dispatch = {
            ScanPhase.RECON: self._run_recon,
            ScanPhase.INTEL: self._run_intel,
            ScanPhase.EXPLOIT: self._run_exploit,
            ScanPhase.REPORT: self._run_report,
        }
        handler = dispatch.get(phase)
        return handler(session) if handler else {}

    # ── per-phase handlers ────────────────────────────────────────────

    def _run_recon(self, session: ScanSession) -> Dict:
        from cyberai.agents.recon.agent import ReconAgent

        agent = ReconAgent(self.config, session, self._client_for(ScanPhase.RECON), self.audit)
        result = agent.run(session.target)
        session.kb_set("recon", result)
        return result

    def _run_intel(self, session: ScanSession) -> Dict:
        from cyberai.agents.intel.agent import IntelAgent

        agent = IntelAgent(self.config, session, self._client_for(ScanPhase.INTEL), self.audit)
        result = agent.run(session.target)
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

        agent = ExploitAgent(self.config, session, self._client_for(ScanPhase.EXPLOIT), self.audit)
        result = agent.run(session.target)
        session.kb_set("exploit", result)
        return result

    def _run_report(self, session: ScanSession) -> Dict:
        from cyberai.agents.report.agent import ReportAgent
        from cyberai.agents.report.html_renderer import render_html_report

        agent = ReportAgent(self.config, session, self._client_for(ScanPhase.REPORT), self.audit)
        result = agent.run(session.target)
        session.kb_set("report", result)

        output = f"report_{session.session_id}.html"
        render_html_report(session.summary(), session.kb, output_path=output)
        console.print(f"[dim]HTML report: {output}[/dim]")
        return {**result, "html_report": output}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AsyncOrchestrator(Orchestrator):
    """
    Async variant of Orchestrator.

    Phases run sequentially (each depends on the previous), but recon
    runs its tools concurrently via AsyncReconAgent. Intel/exploit/report
    still use the sync agents under asyncio.to_thread — gradual rollout
    until those agents gain native async paths.
    """

    async def run(
        self,
        target: str,
        authorized_scope: Optional[List[str]] = None,
    ) -> ScanSession:
        session = ScanSession(
            target=target,
            authorized_scope=authorized_scope or [],
        )
        console.print(
            Panel(
                f"[bold red]CyberAI AsyncOrchestrator[/bold red]\n"
                f"Target  : [yellow]{target}[/yellow]\n"
                f"Phases  : [yellow]{[p.value for p in self.phases]}[/yellow]\n"
                f"Scope   : [yellow]{session.authorized_scope or 'not set'}[/yellow]\n"
                f"Dry Run : [yellow]{self.dry_run}[/yellow]\n"
                f"Session : [dim]{session.session_id}[/dim]",
                border_style="red",
            )
        )
        session.start()
        log.info(f"Async pipeline started — target={target} session={session.session_id}")
        self.audit = AuditLogger(session_id=session.session_id)

        for phase in self.phases:
            await self._run_phase_async(session, phase)
            if session.phases and not session.phases[-1].success:
                log.warning(f"Phase {phase.value} failed — continuing pipeline")

        if session.phases and all(p.success for p in session.phases):
            session.complete()
            console.print("[bold green]✓ Async pipeline complete[/bold green]")
        else:
            failed = [p.phase.value for p in session.phases if not p.success]
            session.fail(f"Failed phases: {failed}")
            console.print(f"[bold red]✗ Async pipeline finished with errors: {failed}[/bold red]")
        log.info(f"Async pipeline done — state={session.state.value}")
        return session

    async def _run_phase_async(self, session: ScanSession, phase: ScanPhase) -> None:
        console.print(f"\n[bold red]▶ {phase.value.upper()}[/bold red]")
        started = _now()
        session.set_phase(phase)
        try:
            if self.dry_run:
                data = {"dry_run": True, "phase": phase.value}
            else:
                data = await self._dispatch_async(session, phase)
                self._check_phase_injection(session, phase, data)
            session.record_phase(phase, success=True, started=started, data=data)
            console.print(f"[green]✓ {phase.value} done[/green]")
        except Exception as exc:  # noqa: BLE001
            session.record_phase(phase, success=False, started=started, error=str(exc))
            console.print(f"[red]✗ {phase.value} error: {exc}[/red]")
            log.error(f"Phase {phase.value} raised", exc_info=True)

    async def _dispatch_async(self, session: ScanSession, phase: ScanPhase) -> Dict[str, Any]:
        if phase == ScanPhase.RECON:
            return await self._run_recon_async(session)
        # Sync agents — offload to a thread so the event loop stays free.
        sync_dispatch = {
            ScanPhase.INTEL: self._run_intel,
            ScanPhase.EXPLOIT: self._run_exploit,
            ScanPhase.REPORT: self._run_report,
        }
        handler = sync_dispatch.get(phase)
        if not handler:
            return {}
        return await asyncio.to_thread(handler, session)

    async def _run_recon_async(self, session: ScanSession) -> Dict:
        from cyberai.agents.recon.async_agent import AsyncReconAgent

        agent = AsyncReconAgent()
        result = await agent.run(session.target)
        session.kb_set("recon", result)
        # Mirror sync ReconAgent granular KB wiring so downstream sync agents
        # (offloaded via asyncio.to_thread) can read recon.* keys.
        for _sub in ("nmap", "dns", "subdomains", "tls"):
            if _sub in result:
                session.kb.set(f"recon.{_sub}", result[_sub], agent="async_recon")
        return result
