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


class TestCachePricing:
    """Anthropic prompt caching: write @ 1.25x input, read @ 0.10x input."""

    def test_cache_write_costs_125_percent_of_input(self):
        # claude-sonnet-4-6 input = $3/M
        # cache write 1M tokens = $3 * 1.25 = $3.75
        cost = price_call(
            "claude-sonnet-4-6",
            0,
            0,
            cache_creation_tokens=1_000_000,
            cache_read_tokens=0,
        )
        assert abs(cost - 3.75) < 1e-9

    def test_cache_read_costs_10_percent_of_input(self):
        # claude-sonnet-4-6 input = $3/M
        # cache read 1M tokens = $3 * 0.10 = $0.30
        cost = price_call(
            "claude-sonnet-4-6",
            0,
            0,
            cache_creation_tokens=0,
            cache_read_tokens=1_000_000,
        )
        assert abs(cost - 0.30) < 1e-9

    def test_mixed_cached_and_regular_input(self):
        # claude-opus-4-7: in=$5/M, out=$25/M
        # 10k regular input @ $5/M       = 0.050
        # 5k output @ $25/M              = 0.125
        # 100k cache_creation @ $5*1.25  = 0.625
        # 50k cache_read @ $5*0.10       = 0.025
        # total = 0.825
        cost = price_call(
            "claude-opus-4-7",
            10_000,
            5_000,
            cache_creation_tokens=100_000,
            cache_read_tokens=50_000,
        )
        assert abs(cost - 0.825) < 1e-9

    def test_cache_savings_vs_uncached_call(self):
        # Same total prompt content, but one is fully cached on second call.
        # First call: full input bill + cache write surcharge
        # Second call: tiny non-cached delta + 10% cache read
        first = price_call(
            "claude-sonnet-4-6",
            500,
            200,
            cache_creation_tokens=10_000,  # written to cache
        )
        second = price_call(
            "claude-sonnet-4-6",
            500,
            200,
            cache_read_tokens=10_000,  # served from cache
        )
        # First call: 0.0015 in + 0.003 out + 0.0375 cache_write = 0.042
        # Second call: 0.0015 in + 0.003 out + 0.003 cache_read = 0.0075
        # Second call must be much cheaper.
        assert second < first
        assert second < first * 0.25  # roughly 4x+ cheaper

    def test_price_usage_handles_cache_fields(self):
        u = TokenUsage(
            agent="exploit",
            model="claude-opus-4-7",
            input_tokens=1_000,
            output_tokens=500,
            cache_creation_tokens=10_000,
            cache_read_tokens=5_000,
        )
        # 1k in @ $5/M = 0.005
        # 0.5k out @ $25/M = 0.0125
        # 10k cache_write @ $5 * 1.25 = 0.0625
        # 5k cache_read @ $5 * 0.10 = 0.0025
        # total = 0.0825
        assert abs(price_usage(u) - 0.0825) < 1e-9
