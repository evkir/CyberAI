"""The configured temperature reaches the Anthropic SDK on every path.

Measured before this existed: none of the four Anthropic branches put
temperature in the kwargs it hands to messages.create, so CYBERAI_TEMPERATURE
selected a value the provider never saw and every Anthropic run sampled at
the API default. The OpenAI branches had carried it since they were written,
which is why nothing looked wrong from the config side -- the field had a
consumer, just not on this provider.

Each test drives the real method and reads what the SDK was called with.
"""

import asyncio
from unittest.mock import MagicMock, patch

from cyberai.core.config import LLMConfig
from cyberai.core.llm_client import LLMClient

TEMP = 0.37


def _config() -> LLMConfig:
    return LLMConfig(
        provider="anthropic", model="claude-sonnet-4-6", api_key="sk-test", temperature=TEMP
    )


def _response(*blocks) -> MagicMock:
    resp = MagicMock()
    resp.content = list(blocks)
    resp.model = "claude-sonnet-4-6"
    resp.stop_reason = "end_turn"
    resp.usage.input_tokens = 10
    resp.usage.output_tokens = 5
    resp.usage.cache_creation_input_tokens = 0
    resp.usage.cache_read_input_tokens = 0
    return resp


def _text_block(text: str = "hi") -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _tool_block(payload: dict) -> MagicMock:
    block = MagicMock()
    block.type = "tool_use"
    block.id = "call_1"
    block.name = "response"
    block.input = payload
    return block


def test_call_sends_the_configured_temperature():
    with patch("anthropic.Anthropic") as sdk:
        create = sdk.return_value.messages.create
        create.return_value = _response(_text_block())
        LLMClient(_config()).call([{"role": "user", "content": "x"}])
    assert create.call_args.kwargs["temperature"] == TEMP


def test_call_tools_sends_the_configured_temperature():
    with patch("anthropic.Anthropic") as sdk:
        create = sdk.return_value.messages.create
        create.return_value = _response(_text_block())
        LLMClient(_config()).call_tools([{"role": "user", "content": "x"}], tools=[])
    assert create.call_args.kwargs["temperature"] == TEMP


def test_structured_call_sends_the_configured_temperature():
    with patch("anthropic.Anthropic") as sdk:
        create = sdk.return_value.messages.create
        create.return_value = _response(_tool_block({"ok": True}))
        out = LLMClient(_config()).structured_call([{"role": "user", "content": "x"}], schema={})
    assert out == {"ok": True}
    assert create.call_args.kwargs["temperature"] == TEMP


def test_acall_sends_the_configured_temperature():
    async def _create(**kwargs):
        _create.kwargs = kwargs
        return _response(_text_block())

    with patch("anthropic.AsyncAnthropic") as sdk:
        sdk.return_value.messages.create = _create
        asyncio.run(LLMClient(_config()).acall([{"role": "user", "content": "x"}]))
    assert _create.kwargs["temperature"] == TEMP


def test_a_wrong_temperature_would_be_visible():
    """Control: the assertions above read the call, not a constant."""
    cfg = _config()
    cfg.temperature = 0.99
    with patch("anthropic.Anthropic") as sdk:
        create = sdk.return_value.messages.create
        create.return_value = _response(_text_block())
        LLMClient(cfg).call([{"role": "user", "content": "x"}])
    assert create.call_args.kwargs["temperature"] == 0.99
