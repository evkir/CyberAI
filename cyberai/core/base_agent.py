"""
BaseAgent — abstract base for all CyberAI agents.

This redesign gives agents an explicit dependency on the session.

Every agent now receives explicit dependencies (config, session, llm,
audit) and exposes the attributes agents actually use:
  self.config, self.session, self.kb, self.llm, self.audit, self.memory
plus helper methods _check_iteration_limit() and _log().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from rich.console import Console

from .config import CyberAIConfig
from .knowledge_base import KnowledgeBase
from .logger import AuditLogger

if TYPE_CHECKING:
    from .llm_client import LLMClient
    from .scan_session import ScanSession

console = Console()


# ── Tool ──────────────────────────────────────────────────────────────


@dataclass
class Tool:
    """
    A callable capability an agent can invoke.

    `params` is the canonical field. `parameters` is accepted as an
    alias for backward compatibility — all existing agents register
    tools with `parameters=...` (KI-6). Pass either; they are kept
    in sync.
    """

    name: str
    description: str
    func: Callable
    params: Dict[str, str] = field(default_factory=dict)
    parameters: Optional[Dict[str, str]] = None
    # Explicit JSON Schema for native LLM tool calling. params expresses only
    # flat string args; set this for typed/nested/list args (KI: build_chain).
    input_schema: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        # KI-6: agents pass parameters=...; mirror it into params.
        if self.parameters is not None and not self.params:
            self.params = self.parameters
        # Keep parameters readable as an alias too.
        self.parameters = self.params


# ── AgentMemory ───────────────────────────────────────────────────────


class AgentMemory:
    """
    Minimal multi-turn conversation memory for agents that talk to an LLM
    across several steps (ExploitAgent in particular — KI-4).
    """

    def __init__(self) -> None:
        self._messages: List[Dict[str, str]] = []
        self._system: Optional[str] = None

    def add(self, role: str, content: str) -> None:
        """Add a message. role='system' is stored separately."""
        if role == "system":
            self._system = content
        else:
            self._messages.append({"role": role, "content": content})

    def to_messages(self) -> List[Dict[str, str]]:
        """Return the message list (excluding system) for an LLM call."""
        return list(self._messages)

    @property
    def system(self) -> Optional[str]:
        return self._system

    def clear(self) -> None:
        self._messages.clear()
        self._system = None


# ── AgentIterationLimitError ──────────────────────────────────────────


class AgentIterationLimitError(RuntimeError):
    """Raised when an agent exceeds config.max_agent_iterations."""


# ── BaseAgent ─────────────────────────────────────────────────────────


class BaseAgent(ABC):
    """
    Abstract base class for all CyberAI agents.

    Agents are constructed with explicit dependencies so they are easy
    to test (everything is injectable / mockable):

        agent = ReconAgent(config, session, llm, audit)
        result = agent.run(target)
    """

    AGENT_NAME: str = "base"
    ROLE: str = "Generic Agent"

    def __init__(
        self,
        config: CyberAIConfig,
        session: "ScanSession",
        llm: Optional["LLMClient"] = None,
        audit: Optional[AuditLogger] = None,
    ) -> None:
        self.config = config
        self.session = session
        self.llm = llm
        # KB is taken from the session if present, else a fresh one.
        self.kb: KnowledgeBase = getattr(session, "kb", None) or KnowledgeBase()
        if not isinstance(self.kb, KnowledgeBase):
            # legacy ScanSession.kb may be a plain dict — wrap it
            self.kb = KnowledgeBase()
        self.audit = audit or AuditLogger(session_id=getattr(session, "session_id", "unknown"))
        self.memory = AgentMemory()

        self.tools: Dict[str, Tool] = {}
        self._iterations: int = 0

        self._register_tools()

    # ── tool registry ─────────────────────────────────────────────────

    def register_tool(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    @abstractmethod
    def _register_tools(self) -> None:
        """Register agent-specific tools."""

    @abstractmethod
    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main agent execution — returns a result dict."""

    def call_tool(self, tool_name: str, **kwargs: Any) -> Any:
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not registered in {self.AGENT_NAME}")
        tool = self.tools[tool_name]
        self.audit.agent_action(self.AGENT_NAME, f"calling tool: {tool_name}", kwargs)
        console.print(f"[dim cyan][{self.AGENT_NAME}] → {tool_name}[/dim cyan]")
        return tool.func(**kwargs)

    # ── iteration safety ──────────────────────────────────────────────

    def _check_iteration_limit(self) -> None:
        """
        Increment the step counter and raise if the agent has exceeded
        config.max_agent_iterations. Called by agents before each major
        step to prevent runaway loops (KI-4).
        """
        self._iterations += 1
        limit = getattr(self.config, "max_agent_iterations", 10)
        if self._iterations > limit:
            raise AgentIterationLimitError(f"{self.AGENT_NAME} exceeded {limit} iterations")

    # ── logging ───────────────────────────────────────────────────────

    def log(self, msg: str, data: Any = None) -> None:
        """Structured log + console echo."""
        self.audit.agent_action(self.AGENT_NAME, msg, data)
        console.print(f"[cyan][{self.AGENT_NAME}][/cyan] {msg}")

    def _log(self, msg: str, data: Any = None) -> None:
        """
        Alias for log(). Several agents call self._log(...) (KI-4).
        Some legacy call sites pass (event, data) — both forms work
        since the first arg is just the message string.
        """
        self.log(msg, data)
