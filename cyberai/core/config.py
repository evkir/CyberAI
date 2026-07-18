from dataclasses import dataclass, field
from typing import Optional, Literal
from pathlib import Path
import json
import os
from dotenv import load_dotenv

load_dotenv()


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


@dataclass
class LLMConfig:
    provider: Literal["openai", "anthropic", "ollama"] = "openai"
    model: str = "gpt-4o"
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.2  # Low temp — we want deterministic pentest reasoning


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
        """Build config from environment variables"""
        provider = os.getenv("CYBERAI_LLM_PROVIDER", "openai")
        model = os.getenv("CYBERAI_MODEL", "gpt-4o")
        return cls(llm=LLMConfig(provider=provider, model=model))
