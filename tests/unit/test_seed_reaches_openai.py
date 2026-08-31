"""A pinned seed reaches the OpenAI SDK on every path, and only when pinned.

CYBERAI_SEED landed in day 16 with a single consumer: the ollama options
dict. The four OpenAI branches passed their arguments positionally to
chat.completions.create and had nowhere to put a conditional one, so a
session that pinned a seed sent it to a local model and silently dropped it
against the hosted one. Anthropic has no seed parameter at all, which is a
property of that API rather than a gap here.

Absence is asserted as well as presence: seed is None by default, and a
null seed is a different request than an unpinned one.
"""

import asyncio
import json
from unittest.mock import MagicMock, patch

from cyberai.core.config import LLMConfig
from cyberai.core.llm_client import LLMClient

SEED = 1337


def _config(seed: int | None = SEED) -> LLMConfig:
    return LLMConfig(provider="openai", model="gpt-4o", api_key="sk-test", seed=seed)


def _response(content: str = "hi", tool_calls=None) -> MagicMock:
    resp = MagicMock()
    resp.model = "gpt-4o"
    resp.usage.prompt_tokens = 10
    resp.usage.completion_tokens = 5
    choice = MagicMock()
    choice.message.content = content
    choice.message.tool_calls = tool_calls
    choice.finish_reason = "stop"
    resp.choices = [choice]
    return resp


def test_call_sends_the_pinned_seed():
    with patch("openai.OpenAI") as sdk:
        create = sdk.return_value.chat.completions.create
        create.return_value = _response()
        LLMClient(_config()).call([{"role": "user", "content": "x"}])
    assert create.call_args.kwargs["seed"] == SEED


def test_call_tools_sends_the_pinned_seed():
    with patch("openai.OpenAI") as sdk:
        create = sdk.return_value.chat.completions.create
        create.return_value = _response()
        LLMClient(_config()).call_tools([{"role": "user", "content": "x"}], tools=[])
    assert create.call_args.kwargs["seed"] == SEED


def test_structured_call_sends_the_pinned_seed():
    with patch("openai.OpenAI") as sdk:
        create = sdk.return_value.chat.completions.create
        create.return_value = _response(json.dumps({"ok": True}))
        out = LLMClient(_config()).structured_call([{"role": "user", "content": "x"}], schema={})
    assert out == {"ok": True}
    assert create.call_args.kwargs["seed"] == SEED


def test_acall_sends_the_pinned_seed():
    async def _create(**kwargs):
        _create.kwargs = kwargs
        return _response()

    with patch("openai.AsyncOpenAI") as sdk:
        sdk.return_value.chat.completions.create = _create
        asyncio.run(LLMClient(_config()).acall([{"role": "user", "content": "x"}]))
    assert _create.kwargs["seed"] == SEED


def test_an_unpinned_seed_is_not_sent_at_all():
    """None means 'not pinned'. Sending seed=null would ask for something."""
    with patch("openai.OpenAI") as sdk:
        create = sdk.return_value.chat.completions.create
        create.return_value = _response()
        LLMClient(_config(seed=None)).call([{"role": "user", "content": "x"}])
    assert "seed" not in create.call_args.kwargs
    assert create.call_args.kwargs["temperature"] == LLMConfig.temperature
