from typing import List, Dict, Optional, Any
from .config import LLMConfig
from .cost_tracker import CostTracker
import httpx


class LLMClient:
    """
    Unified LLM interface — OpenAI / Anthropic / Ollama
    One call() method regardless of provider.
    """

    def __init__(self, config: LLMConfig, cost_tracker: Optional[CostTracker] = None):
        self.config = config
        self.cost_tracker = cost_tracker

    def _record_usage(
        self, agent_name: str, model: str, input_tokens: int, output_tokens: int
    ) -> None:
        """Append usage to the tracker if one was supplied; otherwise a no-op."""
        if self.cost_tracker is not None:
            self.cost_tracker.add(agent_name, model, input_tokens, output_tokens)

    def call(
        self, messages: List[Dict], system: Optional[str] = None, agent_name: str = "unknown"
    ) -> str:
        if self.config.provider == "openai":
            return self._call_openai(messages, system, agent_name)
        elif self.config.provider == "anthropic":
            return self._call_anthropic(messages, system, agent_name)
        elif self.config.provider == "ollama":
            return self._call_ollama(messages, system)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    def _call_openai(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        import openai

        client = openai.OpenAI(api_key=self.config.api_key)
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        response = client.chat.completions.create(
            model=self.config.model,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "prompt_tokens", 0),
            getattr(response.usage, "completion_tokens", 0),
        )
        return response.choices[0].message.content

    def _call_anthropic(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self.config.api_key)
        kwargs: Dict[str, Any] = dict(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
        )
        if system:
            kwargs["system"] = system
        response = client.messages.create(**kwargs)
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
        )
        return response.content[0].text

    def _call_ollama(self, messages: List[Dict], system: Optional[str]) -> str:
        url = f"{self.config.base_url or 'http://localhost:11434'}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
        }
        response = httpx.post(url, json=payload, timeout=60)
        response.raise_for_status()
        return response.json()["message"]["content"]

    # ── async API ─────────────────────────────────────────────────────

    async def acall(
        self, messages: List[Dict], system: Optional[str] = None, agent_name: str = "unknown"
    ) -> str:
        """Async equivalent of call() — same return type, same provider routing."""
        if self.config.provider == "openai":
            return await self._acall_openai(messages, system, agent_name)
        elif self.config.provider == "anthropic":
            return await self._acall_anthropic(messages, system, agent_name)
        elif self.config.provider == "ollama":
            return await self._acall_ollama(messages, system)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    async def _acall_openai(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        import openai

        client = openai.AsyncOpenAI(api_key=self.config.api_key)
        full_messages = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)
        response = await client.chat.completions.create(
            model=self.config.model,
            messages=full_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
        )
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "prompt_tokens", 0),
            getattr(response.usage, "completion_tokens", 0),
        )
        return response.choices[0].message.content

    async def _acall_anthropic(
        self, messages: List[Dict], system: Optional[str], agent_name: str = "unknown"
    ) -> str:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=self.config.api_key)
        kwargs: Dict[str, Any] = dict(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            messages=messages,
        )
        if system:
            kwargs["system"] = system
        response = await client.messages.create(**kwargs)
        self._record_usage(
            agent_name,
            getattr(response, "model", self.config.model),
            getattr(response.usage, "input_tokens", 0),
            getattr(response.usage, "output_tokens", 0),
        )
        return response.content[0].text

    async def _acall_ollama(self, messages: List[Dict], system: Optional[str]) -> str:
        url = f"{self.config.base_url or 'http://localhost:11434'}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()["message"]["content"]
