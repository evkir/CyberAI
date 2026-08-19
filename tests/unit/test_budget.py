"""Budget enforcement: LLMClient must raise BudgetExceeded when configured cap is crossed."""

from unittest.mock import MagicMock, patch

import pytest

from cyberai.core.config import LLMConfig
from cyberai.core.cost_tracker import BudgetExceeded, CostTracker
from cyberai.core.llm_client import LLMClient


def _client_with_budget(budget: float) -> LLMClient:
    cfg = LLMConfig(provider="openai", model="gpt-4o", api_key="sk-test")
    return LLMClient(cfg, cost_tracker=CostTracker(), budget_usd=budget)


def _mock_openai_response(input_tokens: int, output_tokens: int) -> MagicMock:
    msg = MagicMock()
    msg.message.content = "ok"
    resp = MagicMock()
    resp.choices = [msg]
    resp.model = "gpt-4o"
    resp.usage.prompt_tokens = input_tokens
    resp.usage.completion_tokens = output_tokens
    return resp


class TestBudgetEnforcement:
    def test_no_budget_no_check(self):
        """budget_usd=0 disables the gate even if cost would exceed reasonable limits."""
        client = _client_with_budget(0.0)
        # 1M input @ $2.50 + 1M output @ $10 = $12.50
        with patch("openai.OpenAI") as MockOpenAI:
            MockOpenAI.return_value.chat.completions.create.return_value = _mock_openai_response(
                1_000_000, 1_000_000
            )
            client.call([{"role": "user", "content": "hi"}], agent_name="exploit")
        # Should not raise; tracker recorded the call.
        assert client.cost_tracker.call_count == 1

    def test_budget_not_exceeded_passes(self):
        """Spending under the cap is fine."""
        client = _client_with_budget(budget=1.0)  # $1 budget
        with patch("openai.OpenAI") as MockOpenAI:
            MockOpenAI.return_value.chat.completions.create.return_value = (
                _mock_openai_response(10_000, 5_000)  # 0.025 + 0.05 = $0.075
            )
            client.call([{"role": "user", "content": "hi"}], agent_name="exploit")
        assert client.cost_tracker.call_count == 1

    def test_budget_exceeded_raises(self):
        """Crossing the cap on a single call must raise BudgetExceeded."""
        client = _client_with_budget(budget=0.10)  # $0.10
        with patch("openai.OpenAI") as MockOpenAI:
            MockOpenAI.return_value.chat.completions.create.return_value = (
                _mock_openai_response(50_000, 20_000)  # 0.125 + 0.20 = $0.325
            )
            with pytest.raises(BudgetExceeded) as exc_info:
                client.call([{"role": "user", "content": "hi"}], agent_name="exploit")

        assert exc_info.value.budget_usd == 0.10
        assert exc_info.value.spent_usd > 0.10

    def test_cumulative_budget_check(self):
        """Budget tracks across multiple calls, not just per-call."""
        client = _client_with_budget(budget=0.20)
        with patch("openai.OpenAI") as MockOpenAI:
            # Each call costs $0.075; third call pushes total to $0.225 > $0.20.
            MockOpenAI.return_value.chat.completions.create.return_value = _mock_openai_response(
                10_000, 5_000
            )
            client.call([{"role": "user", "content": "1"}], agent_name="exploit")
            client.call([{"role": "user", "content": "2"}], agent_name="exploit")
            with pytest.raises(BudgetExceeded):
                client.call([{"role": "user", "content": "3"}], agent_name="exploit")

        assert client.cost_tracker.call_count == 3
