from typing import List, Dict, Optional, Any
from .config import LLMConfig
import httpx


class LLMClient:
    """
    Unified LLM interface — OpenAI / Anthropic / Ollama
    One call() method regardless of provider.
    """

    def __init__(self, config: LLMConfig):
        self.config = config

    def call(self, messages: List[Dict], system: Optional[str] = None) -> str:
        if self.config.provider == "openai":
            return self._call_openai(messages, system)
        elif self.config.provider == "anthropic":
            return self._call_anthropic(messages, system)
        elif self.config.provider == "ollama":
            return self._call_ollama(messages, system)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    def _call_openai(self, messages: List[Dict], system: Optional[str]) -> str:
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
        return response.choices[0].message.content

    def _call_anthropic(self, messages: List[Dict], system: Optional[str]) -> str:
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
