"""
Prompt caching: verify LLMClient sends the correct cache_control payload,
extracts cache_creation_input_tokens / cache_read_input_tokens, and that
the billed cost on cache hits is materially lower than on cache writes.
"""

from unittest.mock import MagicMock, patch

from cyberai.core.config import LLMConfig
from cyberai.core.cost_tracker import CostTracker
from cyberai.core.llm_client import LLMClient, _wrap_cacheable
from cyberai.core.pricing import price_usage


def _mock_anthropic_response(
    text: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation: int = 0,
    cache_read: int = 0,
) -> MagicMock:
    block = MagicMock()
    block.text = text
    resp = MagicMock()
    resp.content = [block]
    resp.model = "claude-sonnet-4-6"
    resp.usage.input_tokens = input_tokens
    resp.usage.output_tokens = output_tokens
    resp.usage.cache_creation_input_tokens = cache_creation
    resp.usage.cache_read_input_tokens = cache_read
    return resp


def _client() -> LLMClient:
    cfg = LLMConfig(provider="anthropic", model="claude-sonnet-4-6", api_key="sk-test")
    return LLMClient(cfg, cost_tracker=CostTracker())


class TestWrapCacheable:
    def test_shape_matches_anthropic_spec(self):
        wrapped = _wrap_cacheable("system text")
        assert wrapped == [
            {
                "type": "text",
                "text": "system text",
                "cache_control": {"type": "ephemeral"},
            }
        ]


class TestCacheControlPayload:
    def test_cacheable_system_wraps_in_list_with_cache_control(self):
        """When cacheable_system=True, the SDK must receive the cache_control payload."""
        client = _client()
        with patch("anthropic.Anthropic") as MockAnthropic:
            mock_create = MockAnthropic.return_value.messages.create
            mock_create.return_value = _mock_anthropic_response(
                "ok", input_tokens=500, output_tokens=100, cache_creation=2000
            )
            client.call(
                messages=[{"role": "user", "content": "hi"}],
                system="big system prompt over 1024 tokens...",
                agent_name="exploit",
                cacheable_system=True,
            )

        kwargs = mock_create.call_args.kwargs
        assert isinstance(kwargs["system"], list)
        assert kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}

    def test_plain_system_when_cacheable_disabled(self):
        """Without cacheable_system=True, system stays a plain string."""
        client = _client()
        with patch("anthropic.Anthropic") as MockAnthropic:
            mock_create = MockAnthropic.return_value.messages.create
            mock_create.return_value = _mock_anthropic_response(
                "ok", input_tokens=500, output_tokens=100
            )
            client.call(
                messages=[{"role": "user", "content": "hi"}],
                system="short prompt",
                agent_name="exploit",
            )

        kwargs = mock_create.call_args.kwargs
        assert kwargs["system"] == "short prompt"


class TestCacheTokensRecorded:
    def test_cache_creation_and_read_flow_into_tracker(self):
        """First call writes cache; tracker records cache_creation_tokens."""
        client = _client()
        with patch("anthropic.Anthropic") as MockAnthropic:
            mock_create = MockAnthropic.return_value.messages.create
            # Call 1: cache write
            mock_create.return_value = _mock_anthropic_response(
                "first", input_tokens=200, output_tokens=80, cache_creation=1500
            )
            client.call(
                messages=[{"role": "user", "content": "1"}],
                system="big system",
                agent_name="exploit",
                cacheable_system=True,
            )
            # Call 2: cache hit
            mock_create.return_value = _mock_anthropic_response(
                "second", input_tokens=200, output_tokens=80, cache_read=1500
            )
            client.call(
                messages=[{"role": "user", "content": "2"}],
                system="big system",
                agent_name="exploit",
                cacheable_system=True,
            )

        calls = client.cost_tracker.calls
        assert len(calls) == 2

        # First call: cache write recorded, read = 0
        assert calls[0].cache_creation_tokens == 1500
        assert calls[0].cache_read_tokens == 0
        # Second call: cache read recorded, write = 0
        assert calls[1].cache_creation_tokens == 0
        assert calls[1].cache_read_tokens == 1500


class TestCacheReducesCost:
    def test_cache_read_call_is_materially_cheaper_than_cache_write_call(self):
        """The whole point of caching: second-call cost << first-call cost."""
        client = _client()
        with patch("anthropic.Anthropic") as MockAnthropic:
            mock_create = MockAnthropic.return_value.messages.create
            mock_create.return_value = _mock_anthropic_response(
                "first", input_tokens=200, output_tokens=80, cache_creation=10_000
            )
            client.call(
                messages=[{"role": "user", "content": "1"}],
                system="big system",
                agent_name="exploit",
                cacheable_system=True,
            )
            mock_create.return_value = _mock_anthropic_response(
                "second", input_tokens=200, output_tokens=80, cache_read=10_000
            )
            client.call(
                messages=[{"role": "user", "content": "2"}],
                system="big system",
                agent_name="exploit",
                cacheable_system=True,
            )

        first_cost = price_usage(client.cost_tracker.calls[0])
        second_cost = price_usage(client.cost_tracker.calls[1])

        # Cache read is 0.10x base input; cache write is 1.25x base input.
        # Second call MUST be cheaper, and by a wide margin given a 10k-token cached prefix.
        assert second_cost < first_cost
        assert second_cost < first_cost * 0.4, (
            f"expected >2.5x savings, got first={first_cost:.6f} second={second_cost:.6f}"
        )
