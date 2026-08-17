"""
Agent-driven engine runner: measure the pipeline, judged by an independent probe.

The `real` engine runs fixed exploit checks written next to the targets, so it
answers "are these targets exploitable and is the harness sound" — a useful
question, but not the one that matters for the product. This engine answers the
other one: does CyberAI itself, through its own agents, find and prove the
vulnerability with no prior knowledge of the target beyond its URL?

Two independent mechanisms run against every target:

  - the attacker  — ReconAgent discovers the HTTP surface, ExploitAgent attacks
    it, and a finding requires a proof that held: in the response body, or
    out of band when the vector is blind. `solved`
    reports the agent's verdict, because the agent is what is being measured.
  - the judge     — the same per-class probe the `real` engine uses, run
    separately and never consulted by the attacker.

Their disagreement is a finding in itself and is recorded rather than smoothed
over. Agent solved and judge did not: either the agent proved something the
probe cannot see, or a proof is weaker than it looks. Judge solved and agent did
not: the target is exploitable and the pipeline missed it — the honest gap, and
the number worth driving down.

The agent path is deliberately narrow: bench containers publish one HTTP app and
nothing else, so a port scan, whois and DNS enumeration would add minutes and no
information. It calls the web branch of each agent directly, which is the same
code the full pipeline runs behind `use_web_recon` / `use_web_exploit`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Optional

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.agents.exploit.web_payloads import classes_from_description
from cyberai.agents.recon.agent import ReconAgent
from cyberai.bench.docker_builder import DockerBuilder
from cyberai.bench.evaluator import probe_for
from cyberai.bench.runner import BenchResult, BenchTask
from cyberai.bench.targets import LocalSuiteAdapter, VulnTarget
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AttackOutcome:
    """What the agents proved against one live target."""

    confirmed: int = 0
    endpoints_tested: int = 0
    requests_sent: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    oob_confirmed: int = 0

    @property
    def solved(self) -> bool:
        """A target counts as solved when a proof held, on the wire or off it.

        A blind vector produces no proof in the response by definition: the
        local SSRF target answers identically either way, and its declared
        success signal is a callback carrying the run nonce. Counting only
        in-band proofs would score that target unsolvable for the agent while
        the probe solves it every time -- a gap in the criterion read as a gap
        in the pipeline.
        """
        return self.confirmed > 0 or self.oob_confirmed > 0


# An attacker drives CyberAI against a live base_url and reports what it proved.
AttackFn = Callable[[str, BenchTask], AttackOutcome]
# A judge decides, independently of the attacker, whether the target fell.
JudgeFn = Callable[[VulnTarget, str], bool]


def agent_attack(
    base_url: str,
    task: Optional[BenchTask] = None,
    config: Optional[CyberAIConfig] = None,
    one_day: bool = False,
) -> AttackOutcome:
    """Run the agent web path against `base_url` and report proven findings.

    Both agents share one ScanSession, so the exploit agent reads the surface
    out of the same knowledge base the recon agent wrote it to. That seam is
    the thing under measurement: a runner that called the modules directly
    would still pass while the agents were wired to different keys.

    The config comes from the environment so every other flag reaches the
    bench: building it from defaults instead silently pinned each new
    capability to off here, and a run would report the pipeline missing what
    it was never allowed to try. Three flags are forced on regardless: the
    two web ones, because the web path is the whole measurement, and the
    out-of-band one, because a blind target is unscoreable without it.

    `one_day` is what makes the second mode a choice rather than a side
    effect. The description rides along in every task once the loader keeps
    it, so reading it whenever it is present would have quietly turned every
    past zero-day number into something else while the label stayed the same.
    A published score has to stay reproducible by the command that produced
    it, so the knowledge is used only when the caller asks for it.
    """
    # The bench profile turns on what the measured path needs. use_oob is
    # the third of those: one suite target is blind, so without it the
    # agent fails a task it solves. The cost is bounded -- oob_max_params
    # caps confirmation at 3 parameters, _OOB_MAX_WAIT at 5s each -- so a
    # task pays at most 15s for a capability it needs to be scored fairly.
    cfg = config or replace(
        CyberAIConfig.from_env(),
        use_web_recon=True,
        use_web_exploit=True,
        use_oob=True,
    )
    session = ScanSession(target=base_url)

    description = str((task.metadata if task else {}).get("one_day_description", ""))
    classes = classes_from_description(description) if one_day and description else None

    ReconAgent(cfg, session)._run_web_recon(base_url)
    report = ExploitAgent(cfg, session)._run_web_exploit(base_url, classes=classes)

    return AttackOutcome(
        confirmed=int(report.get("confirmed", 0)),
        endpoints_tested=int(report.get("endpoints_tested", 0)),
        requests_sent=int(report.get("requests_sent", 0)),
        findings=list(report.get("findings", [])),
        oob_confirmed=int(report.get("params_oob_confirmed", 0)),
    )


def _judge(judge_fn: JudgeFn, target: VulnTarget, base_url: str) -> Optional[bool]:
    """Run the independent judge; None when the judge itself failed.

    A broken judge must not be reported as "target not exploitable", which is
    exactly the overstatement in reverse: it would silently turn agent misses
    into agreements.
    """
    try:
        return bool(judge_fn(target, base_url))
    except Exception as exc:  # noqa: BLE001 — the judge is advisory, never fatal
        logger.warning("judge probe failed on %s: %s", target.id, exc)
        return None


def make_agent_runner(
    adapter: LocalSuiteAdapter,
    builder: Optional[DockerBuilder] = None,
    attacker: Optional[AttackFn] = None,
    judge: Optional[JudgeFn] = None,
):
    """Build a TaskRunner that measures the agents and cross-checks the probe.

    The returned callable matches runner.TaskRunner: BenchTask -> BenchResult.
    `attacker` and `judge` are injected so tests can drive both verdicts.
    """
    builder = builder or DockerBuilder()
    attack = attacker or agent_attack
    judge_fn = judge or probe_for

    def _run(task: BenchTask) -> BenchResult:
        target = adapter.get_target(task.id)
        if target is None:
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=False,
                error="no VulnTarget for task id (local suite only)",
                details={"engine": "agent"},
            )

        running = builder.start(target)
        if running is None:
            # Docker absent or start failed — honest unsolved, not a fake pass.
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=False,
                error="target not serving (docker unavailable or start failed)",
                details={
                    "engine": "agent",
                    "vuln_class": target.vuln_class.value,
                    "available": False,
                },
            )

        try:
            outcome = attack(running.base_url, task)
            judged = _judge(judge_fn, target, running.base_url)
            details: dict[str, Any] = {
                "engine": "agent",
                "vuln_class": target.vuln_class.value,
                "base_url": running.base_url,
                "available": True,
                "agent_confirmed": outcome.confirmed,
                "oob_confirmed": outcome.oob_confirmed,
                "endpoints_tested": outcome.endpoints_tested,
                "requests_sent": outcome.requests_sent,
                "findings": outcome.findings,
                "judge_solved": judged,
                "agreement": None if judged is None else outcome.solved == judged,
            }
            if judged is not None and judged != outcome.solved:
                details["disagreement"] = (
                    "agent proved it, probe did not"
                    if outcome.solved
                    else "probe proved it, agent missed it"
                )
                logger.warning(
                    "agent/probe disagreement on %s: agent=%s probe=%s",
                    task.id,
                    outcome.solved,
                    judged,
                )
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=outcome.solved,
                details=details,
            )
        except Exception as exc:  # noqa: BLE001 — one bad target must not kill the suite
            logger.warning("agent engine error on %s: %s", task.id, exc)
            return BenchResult(
                task_id=task.id,
                suite=task.suite,
                solved=False,
                error=str(exc),
                details={"engine": "agent", "vuln_class": target.vuln_class.value},
            )
        finally:
            builder.stop(running)

    return _run
