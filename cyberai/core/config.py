from dataclasses import dataclass, field
from typing import Optional, Literal
from pathlib import Path
import json
import os
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
    # Flag-gated: LLM-as-Judge validates the report vs KB evidence.
    use_judge: bool = False
    # Flag-gated: on a phase failure, ask the critic whether to re-run it once.
    enable_replan: bool = False
    # Flag-gated: recall similar past exploit chains from local memory.
    use_exploit_memory: bool = False
    # Flag-gated: profile response timing/patterns to detect honeypot/WAF/tarpit.
    use_behavioral_fingerprint: bool = False
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
        output_dir = Path(out) if out else Path("reports/")
        return cls(
            llm=LLMConfig(provider=provider, model=model),
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
            use_judge=_env_bool("CYBERAI_USE_JUDGE", False),
            enable_replan=_env_bool("CYBERAI_ENABLE_REPLAN", False),
            use_exploit_memory=_env_bool("CYBERAI_USE_EXPLOIT_MEMORY", False),
            use_behavioral_fingerprint=_env_bool("CYBERAI_USE_BEHAVIORAL", False),
            use_lab_dogfood=_env_bool("CYBERAI_USE_LAB_DOGFOOD", False),
            web_enable_bench_trigger=_env_bool("CYBERAI_WEB_ENABLE_BENCH_TRIGGER", False),
            air_gapped=_env_bool("CYBERAI_AIR_GAPPED", False),
        )
