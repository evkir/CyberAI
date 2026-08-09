"""
Local vulnerable-target suite — our own, fully autonomous benchmark targets.

These are CyberAI's own deliberately-vulnerable web apps (built and served by
cyberai/bench/apps/ + the docker builder). They give us a self-contained,
CI-friendly polygon to measure the engine against — no third-party benchmark
required. External suites (CVE-Bench, etc.) are optional adapters layered on
top of the same BenchTask contract, used only for public-leaderboard parity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cyberai.bench.runner import BenchAdapter, BenchTask


class VulnClass(str, Enum):
    """Vulnerability category a local target exposes."""

    SQLI = "sqli"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"


@dataclass(frozen=True)
class VulnTarget:
    """A deliberately-vulnerable app we author and serve for benchmarking.

    `app` is the identifier the docker builder maps to a concrete app under
    cyberai/bench/apps/. `success_signal` describes, in plain terms, what proves
    exploitation; the evaluator turns it into a concrete check.
    """

    id: str
    name: str
    vuln_class: VulnClass
    cwe: str
    port: int
    app: str
    success_signal: str
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_bench_task(self) -> BenchTask:
        """Project this target into the framework-agnostic BenchTask contract."""
        return BenchTask(
            id=self.id,
            suite="local",
            target=f"http://localhost:{self.port}",
            name=self.name,
            success_criteria=self.success_signal,
            metadata={
                "vuln_class": self.vuln_class.value,
                "cwe": self.cwe,
                "app": self.app,
                "port": self.port,
                **self.metadata,
            },
        )


# Our authored mini-suite. Classic, unambiguous classes with crisp success
# signals — chosen so exploitation is binary and CI-reproducible.
LOCAL_SUITE: tuple[VulnTarget, ...] = (
    VulnTarget(
        id="local-sqli-login",
        name="SQLi auth bypass",
        vuln_class=VulnClass.SQLI,
        cwe="CWE-89",
        port=8801,
        app="sqli_login",
        success_signal="authenticated session obtained via SQL injection in the login form",
        description="Login endpoint concatenates credentials into a SQL query unsanitized.",
    ),
    VulnTarget(
        id="local-cmdi-ping",
        name="Command injection in ping tool",
        vuln_class=VulnClass.COMMAND_INJECTION,
        cwe="CWE-78",
        port=8802,
        app="cmdi_ping",
        success_signal="arbitrary command output returned via shell metacharacters in the host field",
        description="Diagnostic endpoint passes a user-supplied host into a shell ping command.",
    ),
    VulnTarget(
        id="local-path-traversal",
        name="Path traversal file read",
        vuln_class=VulnClass.PATH_TRAVERSAL,
        cwe="CWE-22",
        port=8803,
        app="path_traversal",
        success_signal="contents of a file outside the web root read via ../ sequences",
        description="Static-file handler joins a user path without normalization.",
    ),
    VulnTarget(
        id="local-ssrf-fetch",
        name="Blind SSRF in URL fetcher",
        vuln_class=VulnClass.SSRF,
        cwe="CWE-918",
        port=8804,
        app="ssrf_fetch",
        success_signal="out-of-band collector recorded a callback carrying the run nonce",
        description=(
            "Fetch endpoint requests a user-supplied URL and answers identically "
            "whichever way it goes, so only an out-of-band callback proves it."
        ),
    ),
)


class LocalSuiteAdapter(BenchAdapter):
    """Loads CyberAI's own local vulnerable-target suite as BenchTasks."""

    name = "local"

    def __init__(self, targets: tuple[VulnTarget, ...] = LOCAL_SUITE) -> None:
        self._targets = tuple(targets)

    def load_tasks(self) -> list[BenchTask]:
        return [t.to_bench_task() for t in self._targets]

    def get_target(self, target_id: str) -> VulnTarget | None:
        """Resolve the original VulnTarget (with app/port) for a task id."""
        return next((t for t in self._targets if t.id == target_id), None)
