from dataclasses import dataclass, field
from typing import Optional, Literal
from pathlib import Path
import json
import os
from dotenv import load_dotenv

load_dotenv()

@dataclass
class LLMConfig:
    provider: Literal["openai", "anthropic", "ollama"] = "openai"
    model: str = "gpt-4o"
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.2   # Low temp — we want deterministic pentest reasoning

@dataclass
class PhantomConfig:
    intel_db: Path = Path("~/.phantom/intel.db")
    grid_url: str = "http://127.0.0.1:8080"
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
