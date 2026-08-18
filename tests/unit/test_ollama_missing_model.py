"""A default model name cannot be right for every library.

The report agent catches LLM failures by design, so the exception text is the
only place a reader learns why nothing came back. A missing model has to name
itself and the command that installs it.
"""

import httpx
import pytest

from cyberai.core.config import LLMConfig
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.llm_client import LLMClient


class _Response:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


def _client(monkeypatch, response):
    client = LLMClient(
        LLMConfig(provider="ollama", model="absent-model:7b"), cost_tracker=CostTracker()
    )
    monkeypatch.setattr(httpx, "post", lambda *a, **k: response)
    return client


def test_a_missing_model_names_itself_and_the_pull_command(monkeypatch):
    client = _client(monkeypatch, _Response(404, '{"error":"model not found"}'))
    with pytest.raises(RuntimeError) as excinfo:
        client.call([{"role": "user", "content": "hi"}], agent_name="probe")
    message = str(excinfo.value)
    assert "absent-model:7b" in message
    assert "ollama pull absent-model:7b" in message
    assert "--model" in message


def test_other_failures_keep_the_plain_status_line(monkeypatch):
    client = _client(monkeypatch, _Response(500, "boom"))
    with pytest.raises(RuntimeError) as excinfo:
        client.call([{"role": "user", "content": "hi"}], agent_name="probe")
    message = str(excinfo.value)
    assert "ollama HTTP 500" in message
    assert "ollama pull" not in message


def test_a_refused_call_is_still_counted_as_an_attempt(monkeypatch):
    client = _client(monkeypatch, _Response(404, "nope"))
    with pytest.raises(RuntimeError):
        client.call([{"role": "user", "content": "hi"}], agent_name="probe")
    assert client.cost_tracker.attempts == 1
    assert client.cost_tracker.call_count == 0
