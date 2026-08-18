"""LLMClient.call_tools had a live consumer and no test that ran it.

The exploit agent drives its native-tool loop through this method, but every
test so far replaced agent.llm with a mock, so the dispatcher and both
provider paths were never executed. A refusal here would have been as silent
as the one fixed in call().
"""

import pytest

from cyberai.core.base_agent import Tool
from cyberai.core.config import LLMConfig
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.llm_client import LLMClient


def _tool():
    return Tool(
        name="probe",
        description="probe a target",
        func=lambda **kw: None,
        parameters={"target": "str"},
    )


def _client(provider):
    return LLMClient(
        LLMConfig(provider=provider, model="m", api_key="k"), cost_tracker=CostTracker()
    )


def test_an_unsupported_provider_says_so_by_name():
    client = _client("ollama")
    with pytest.raises(ValueError) as excinfo:
        client.call_tools([{"role": "user", "content": "hi"}], tools=[_tool()])
    assert "ollama" in str(excinfo.value)


def test_the_attempt_is_counted_even_when_no_provider_can_serve_it():
    client = _client("ollama")
    with pytest.raises(ValueError):
        client.call_tools([{"role": "user", "content": "hi"}], tools=[_tool()])
    assert client.cost_tracker.attempts == 1
    assert client.cost_tracker.call_count == 0


def test_the_openai_path_returns_the_requested_tool_calls(monkeypatch):
    client = _client("openai")
    captured = {}

    class _Function:
        name = "probe"
        arguments = '{"target": "example.com"}'

    class _ToolCall:
        id = "call_1"
        function = _Function()

    class _Message:
        content = "running the probe"
        tool_calls = [_ToolCall()]

    class _Choice:
        message = _Message()
        finish_reason = "tool_calls"

    class _Usage:
        prompt_tokens = 120
        completion_tokens = 8

    class _Response:
        model = "m"
        choices = [_Choice()]
        usage = _Usage()

    class _Completions:
        def create(self, **kwargs):
            captured.update(kwargs)
            return _Response()

    class _Chat:
        completions = _Completions()

    class _OpenAI:
        def __init__(self, api_key=None):
            self.chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", _OpenAI)
    resp = client.call_tools(
        [{"role": "user", "content": "hi"}], system="be brief", tools=[_tool()]
    )

    assert [c.name for c in resp.tool_calls] == ["probe"]
    assert resp.tool_calls[0].arguments == {"target": "example.com"}
    assert resp.stop_reason == "tool_calls"
    assert client.cost_tracker.call_count == 1
    assert captured["messages"][0]["role"] == "system"
    assert captured["tools"][0]["function"]["name"] == "probe"


def test_unparsable_arguments_do_not_lose_the_call(monkeypatch):
    client = _client("openai")

    class _Function:
        name = "probe"
        arguments = "{not json"

    class _ToolCall:
        id = "call_1"
        function = _Function()

    class _Message:
        content = None
        tool_calls = [_ToolCall()]

    class _Choice:
        message = _Message()
        finish_reason = "tool_calls"

    class _Usage:
        prompt_tokens = 1
        completion_tokens = 1

    class _Response:
        model = "m"
        choices = [_Choice()]
        usage = _Usage()

    class _Completions:
        def create(self, **kwargs):
            return _Response()

    class _Chat:
        completions = _Completions()

    class _OpenAI:
        def __init__(self, api_key=None):
            self.chat = _Chat()

    import openai

    monkeypatch.setattr(openai, "OpenAI", _OpenAI)
    resp = client.call_tools([{"role": "user", "content": "hi"}], tools=[_tool()])

    assert resp.tool_calls[0].name == "probe"
    assert resp.tool_calls[0].arguments == {}


class _Block:
    """Anthropic returns typed content blocks, not a single message."""

    def __init__(self, type, text=None, id=None, name=None, input=None):
        self.type = type
        self.text = text
        self.id = id
        self.name = name
        self.input = input or {}


def _anthropic_client(monkeypatch, blocks, stop_reason="tool_use"):
    captured = {}

    class _Usage:
        input_tokens = 200
        output_tokens = 12
        cache_creation_input_tokens = 0
        cache_read_input_tokens = 0

    class _Response:
        model = "m"
        content = blocks
        usage = _Usage()

    _Response.stop_reason = stop_reason

    class _Messages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return _Response()

    class _Anthropic:
        def __init__(self, api_key=None):
            self.messages = _Messages()

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", _Anthropic)
    return _client("anthropic"), captured


def test_the_anthropic_path_splits_text_from_tool_use(monkeypatch):
    blocks = [
        _Block("text", text="I will probe it."),
        _Block("tool_use", id="tu_1", name="probe", input={"target": "example.com"}),
    ]
    client, captured = _anthropic_client(monkeypatch, blocks)
    resp = client.call_tools(
        [{"role": "user", "content": "hi"}], system="be brief", tools=[_tool()]
    )

    assert resp.text == "I will probe it."
    assert [c.name for c in resp.tool_calls] == ["probe"]
    assert resp.tool_calls[0].arguments == {"target": "example.com"}
    assert resp.stop_reason == "tool_use"
    assert client.cost_tracker.attempts == 1
    assert client.cost_tracker.call_count == 1
    assert captured["system"] == "be brief"


def test_a_cacheable_system_prompt_is_wrapped_before_it_is_sent(monkeypatch):
    blocks = [_Block("text", text="done")]
    client, captured = _anthropic_client(monkeypatch, blocks, stop_reason="end_turn")
    client.call_tools(
        [{"role": "user", "content": "hi"}],
        system="long standing instructions",
        tools=[_tool()],
        cacheable_system=True,
    )

    assert captured["system"] != "long standing instructions"
    assert "long standing instructions" in str(captured["system"])


def test_a_reply_with_no_tool_use_reports_empty_calls(monkeypatch):
    blocks = [_Block("text", text="nothing to run")]
    client, _ = _anthropic_client(monkeypatch, blocks, stop_reason="end_turn")
    resp = client.call_tools([{"role": "user", "content": "hi"}], tools=[_tool()])

    assert resp.tool_calls == []
    assert resp.text == "nothing to run"
