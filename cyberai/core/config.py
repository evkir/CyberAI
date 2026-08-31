"""Typed configuration shared by every agent, CLI entry point and web route.

`CyberAIConfig` is a dataclass: every field declared here exists on every
instance. Consumers therefore read `config.<field>` directly. A `getattr`
fallback is not the house style: while the field is declared the fallback is
unreachable, and it turns a renamed or deleted field into a silent change of
behaviour instead of an AttributeError at the first read.

Values arrive from three places, in this order: the dataclass defaults below,
the environment via `from_env()` and the `_env_*` helpers, and the CLI, which
assigns to declared fields in place (`cyberai/__main__.py`). The CLI never
introduces a field that is not declared here.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean feature flag from the environment.

    Truthy values: 1, true, yes, on (case-insensitive). Any other set value
    is false; an unset variable keeps the caller's default.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    """Read a float setting from the environment; unset/invalid keeps default."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_optional_int(name: str) -> Optional[int]:
    """Read an int setting that may legitimately be unset.

    Returns None for unset, empty or unparseable, because those three all
    mean 'nobody chose a value' and the caller must be able to tell that
    from a chosen 0. Garbage in the variable must not abort a scan on
    startup, so an unparseable value is unset rather than an error.
    """
    raw = os.getenv(name, "")
    try:
        return int(raw)
    except ValueError:
        return None


def _env_int(name: str, default: int) -> int:
    """Read an int setting from the environment; unset/invalid keeps default."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class RoutingConfig:
    """Per-phase model routing. Off by default (no-regression)."""

    enable_model_routing: bool = False
    fast_model: str = "claude-haiku-4-5"
    strong_model: str = "claude-opus-4-8"
    phase_models: dict = field(default_factory=dict)
    # Air-gapped: local endpoint the router forces every phase onto.
    air_gapped_provider: str = "ollama"
    air_gapped_base_url: str = "http://localhost:11434"


# Per-provider default model. Keeps air-gapped ollama runs from inheriting
# a cloud default (e.g. gpt-4o) that the local runtime does not have.
_PROVIDER_DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "anthropic": "claude-opus-4-8",
    "ollama": "qwen2.5:7b",
}


@dataclass
class LLMConfig:
    provider: Literal["openai", "anthropic", "ollama"] = "openai"
    model: str = "gpt-4o"
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.2  # Low temp — we want deterministic pentest reasoning
    # Sampling seed. None means 'not pinned', which is what the runtime
    # does when nobody asks; it is not the same answer as 0. Pinning a
    # seed by default would make every run repeat the previous one
    # without the caller choosing that, and a default that silently
    # changes behaviour is not a default.
    seed: Optional[int] = None
    # Trust boundary settings, consumed by LLMClient when it builds its
    # TrustGuard. None means 'not configured here' and defers to the
    # environment, not 'use the safe default' — the two are different
    # answers and a caller reading this field needs to tell them apart.
    injection_policy: Optional[str] = None
    injection_threshold: Optional[int] = None

    @staticmethod
    def default_model_for(provider: str) -> str:
        """Resolve the sensible default model for a provider."""
        return _PROVIDER_DEFAULT_MODELS.get(provider, "gpt-4o")


@dataclass
class PhantomConfig:
    intel_db: Path = Path("~/.phantom/intel.db")
    grid_url: str = "http://127.0.0.1:9090"
    grid_api_key: Optional[str] = field(default_factory=lambda: os.getenv("PHANTOM_GRID_KEY"))


@dataclass
class IntelConfig:
    nvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))


@dataclass
class CyberAIConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    phantom: PhantomConfig = field(default_factory=PhantomConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    output_dir: Path = Path("reports/")
    verbose: bool = False
    timeout: int = 60
    max_agent_iterations: int = 10
    # Hard budget for total LLM spend in this scan, USD. 0.0 disables the check.
    max_cost_usd: float = 0.0
    # Flag-gated: run the nuclei template engine in ExploitAgent.
    use_nuclei: bool = False
    # Flag-gated: let the model pick and order exploit tools via native tool
    # calling, instead of the deterministic chain builder.
    use_native_tools: bool = False
    # Flag-gated: LLM writes the executive section of the report.
    use_llm_summary: bool = False
    # Flag-gated: LLM-as-Judge validates the report vs KB evidence.
    use_judge: bool = False
    # Flag-gated: on a phase failure, ask the critic whether to re-run it once.
    enable_replan: bool = False
    # Flag-gated: run the PlannerAgent between intel and exploit.
    enable_planner: bool = False
    # Flag-gated: recall similar past exploit chains from local memory.
    use_exploit_memory: bool = False
    # Flag-gated: profile response timing/patterns to detect honeypot/WAF/tarpit.
    use_behavioral_fingerprint: bool = False
    # Flag-gated: grab banners from the ports -sV could not name. Off by
    # default because it changes the network profile, not because it is slow:
    # recon is otherwise passive once nmap has run.
    use_port_fingerprint: bool = False
    # Flag-gated: crawl a web target for injectable endpoints and parameters.
    use_web_recon: bool = False
    # Flag-gated: attack the discovered HTTP surface directly (non-blind).
    use_web_exploit: bool = False
    # Flag-gated: confirm the parameters the direct walk could not read through
    # an out-of-band callback. Off by default because it needs a reachable
    # collector, not because it is expensive: the walk caps confirmation at
    # oob_max_params parameters, each bounded by the poller's wait. The bench
    # profile turns it on, since a blind target cannot be scored without it.
    use_oob: bool = False
    # Flag-gated: read spec and JS bundles when the HTML shell exposes nothing.
    use_api_discovery: bool = False
    # Flag-gated: ask discovered routes whether they read an undeclared
    # parameter. Costs a request per route to establish a negative, so it
    # stays explicit even when api discovery is on.
    use_route_probing: bool = False
    # Flag-gated: attack the endpoints the planner named before the rest.
    use_plan_web_order: bool = False
    # Flag-gated: fuzz the LLM channels the planner named, in the exploit phase.
    use_planned_redteam: bool = False
    exploit_memory_path: Optional[str] = None
    # Flag-gated: parse local practice-lab machine artifacts and detect flags.
    use_lab_dogfood: bool = False
    # Extra regex patterns for the lab flag detector, on top of built-ins.
    lab_flag_patterns: list[str] = field(default_factory=list)
    # Flag-gated: allow the web dashboard to launch a bench run as a subprocess.
    web_enable_bench_trigger: bool = False
    # Root dir holding practice-lab machine folders, read by the lab dashboard.
    lab_machines_dir: Optional[str] = None
    # Hallucination score >= threshold marks the report unsupported.
    judge_threshold: float = 0.7
    # Optional more-powerful model for the judge; None = same as main LLM.
    judge_model: Optional[str] = None
    # Flag-gated: per-phase model routing.
    routing: "RoutingConfig" = field(default_factory=lambda: RoutingConfig())
    # Flag-gated: force all LLM calls onto a local endpoint, assert no egress.
    air_gapped: bool = False
    # Flag-gated: an empty authorized scope becomes a violation instead of a
    # warning, so the exploit phase refuses to run against a target nobody
    # named. Off by default -- see the validator for why.
    strict_scope: bool = False
    # Cap nmap scan rate (packets/sec) on external/legal targets; None = uncapped.
    max_rps: Optional[int] = None
    # Headers every web request carries. A target that refuses an anonymous
    # walk is not clean, only unread; no env variable backs this because a
    # credential in the environment outlives the run that needed it.
    auth_headers: Optional[dict[str, str]] = None
    # Attack state-changing verbs (DELETE/PUT/PATCH) instead of skipping them.
    # Off by default: proving an injection through a DELETE destroys the record
    # that evidences it, and on a live target that is damage taken for nothing.
    allow_destructive: bool = False

    @classmethod
    def from_file(cls, path: str) -> "CyberAIConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2, default=str)

    @classmethod
    def from_env(cls) -> "CyberAIConfig":
        """Build config from environment variables."""
        provider = os.getenv("CYBERAI_LLM_PROVIDER", "openai")
        model = os.getenv("CYBERAI_MODEL") or LLMConfig.default_model_for(provider)
        routing = RoutingConfig(
            enable_model_routing=_env_bool("CYBERAI_ENABLE_MODEL_ROUTING", False),
        )
        out = os.getenv("CYBERAI_OUTPUT_DIR")
        # Left as None when unset or unparseable, so TrustGuard can tell
        # 'not configured' from a real choice. Garbage in the variable
        # must not abort a scan on startup.
        policy = os.getenv("CYBERAI_INJECTION_POLICY") or None
        threshold = _env_optional_int("CYBERAI_INJECTION_THRESHOLD")
        output_dir = Path(out) if out else Path("reports/")
        return cls(
            llm=LLMConfig(
                provider=provider,
                model=model,
                injection_policy=policy,
                injection_threshold=threshold,
                temperature=_env_float("CYBERAI_TEMPERATURE", LLMConfig.temperature),
                seed=_env_optional_int("CYBERAI_SEED"),
            ),
            routing=routing,
            output_dir=output_dir,
            verbose=_env_bool("CYBERAI_VERBOSE", False),
            timeout=_env_int("CYBERAI_TIMEOUT", 60),
            max_agent_iterations=_env_int("CYBERAI_MAX_AGENT_ITERATIONS", 10),
            max_cost_usd=_env_float("CYBERAI_MAX_COST_USD", 0.0),
            judge_threshold=_env_float("CYBERAI_JUDGE_THRESHOLD", 0.7),
            judge_model=os.getenv("CYBERAI_JUDGE_MODEL") or None,
            exploit_memory_path=os.getenv("CYBERAI_EXPLOIT_MEMORY_PATH") or None,
            lab_machines_dir=os.getenv("CYBERAI_LAB_MACHINES_DIR") or None,
            use_nuclei=_env_bool("CYBERAI_USE_NUCLEI", False),
            use_native_tools=_env_bool("CYBERAI_USE_NATIVE_TOOLS", False),
            use_llm_summary=_env_bool("CYBERAI_USE_LLM_SUMMARY", False),
            use_judge=_env_bool("CYBERAI_USE_JUDGE", False),
            enable_replan=_env_bool("CYBERAI_ENABLE_REPLAN", False),
            enable_planner=_env_bool("CYBERAI_ENABLE_PLANNER", False),
            use_exploit_memory=_env_bool("CYBERAI_USE_EXPLOIT_MEMORY", False),
            use_behavioral_fingerprint=_env_bool("CYBERAI_USE_BEHAVIORAL", False),
            use_port_fingerprint=_env_bool("CYBERAI_USE_PORT_FINGERPRINT", False),
            use_web_recon=_env_bool("CYBERAI_USE_WEB_RECON", False),
            use_web_exploit=_env_bool("CYBERAI_USE_WEB_EXPLOIT", False),
            use_oob=_env_bool("CYBERAI_USE_OOB", False),
            use_api_discovery=_env_bool("CYBERAI_USE_API_DISCOVERY", False),
            use_route_probing=_env_bool("CYBERAI_USE_ROUTE_PROBING", False),
            use_plan_web_order=_env_bool("CYBERAI_USE_PLAN_WEB_ORDER", False),
            use_planned_redteam=_env_bool("CYBERAI_USE_PLANNED_REDTEAM", False),
            use_lab_dogfood=_env_bool("CYBERAI_USE_LAB_DOGFOOD", False),
            web_enable_bench_trigger=_env_bool("CYBERAI_WEB_ENABLE_BENCH_TRIGGER", False),
            air_gapped=_env_bool("CYBERAI_AIR_GAPPED", False),
            strict_scope=_env_bool("CYBERAI_STRICT_SCOPE", False),
        )
