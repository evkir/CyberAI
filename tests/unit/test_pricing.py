"""Unit tests for the pricing table and cost computation."""

from cyberai.core.cost_tracker import CostTracker, TokenUsage
from cyberai.core.pricing import PRICING, price_call, price_usage, total_cost


class TestPriceCall:
    def test_gpt_4o_mini_one_million_input(self):
        # $0.15 per 1M input tokens
        assert price_call("gpt-4o-mini", 1_000_000, 0) == 0.15

    def test_gpt_4o_mini_one_million_output(self):
        # $0.60 per 1M output tokens
        assert price_call("gpt-4o-mini", 0, 1_000_000) == 0.60

    def test_claude_opus_4_7_mixed(self):
        # 10k input @ $5/M + 5k output @ $25/M = 0.05 + 0.125 = $0.175
        cost = price_call("claude-opus-4-7", 10_000, 5_000)
        assert abs(cost - 0.175) < 1e-9

    def test_unknown_model_is_free(self):
        assert price_call("llama3.2:latest", 1_000_000, 1_000_000) == 0.0

    def test_zero_tokens_zero_cost(self):
        assert price_call("gpt-4o", 0, 0) == 0.0


class TestPriceUsage:
    def test_price_usage_matches_price_call(self):
        u = TokenUsage(agent="exploit", model="gpt-4o", input_tokens=1000, output_tokens=500)
        # 1000 @ $2.50/M + 500 @ $10/M = 0.0025 + 0.005 = $0.0075
        assert abs(price_usage(u) - 0.0075) < 1e-9


class TestTotalCost:
    def test_empty_tracker_costs_nothing(self):
        assert total_cost(CostTracker()) == 0.0

    def test_total_cost_sums_across_calls(self):
        t = CostTracker()
        t.add("intel", "gpt-4o-mini", 1_000_000, 0)  # $0.15
        t.add("exploit", "gpt-4o", 0, 1_000_000)  # $10.00
        t.add("recon", "claude-haiku-4-5", 1_000_000, 1_000_000)  # $1 + $5 = $6
        # Expected total: 0.15 + 10.00 + 6.00 = 16.15
        assert abs(total_cost(t) - 16.15) < 1e-9


class TestPricingTable:
    def test_anthropic_output_is_5x_input(self):
        """Sanity check: every Claude model has the documented 5x output ratio."""
        for name, p in PRICING.items():
            if name.startswith("claude-"):
                assert p.output_per_mtok == 5 * p.input_per_mtok, (
                    f"{name} broke the 5x ratio: in={p.input_per_mtok}, out={p.output_per_mtok}"
                )

    def test_known_flagship_models_present(self):
        for required in (
            "gpt-4o",
            "gpt-4o-mini",
            "claude-opus-4-7",
            "claude-sonnet-4-6",
            "claude-haiku-4-5",
        ):
            assert required in PRICING, f"missing flagship model: {required}"
