"""Unit tests for CostTracker — tokens only, no pricing yet."""

from cyberai.core.cost_tracker import CostTracker, TokenUsage


class TestCostTracker:
    def test_empty_tracker_starts_at_zero(self):
        t = CostTracker()
        assert t.call_count == 0
        assert t.total_tokens == 0
        assert t.total_input_tokens == 0
        assert t.total_output_tokens == 0

    def test_add_records_usage(self):
        t = CostTracker()
        entry = t.add("exploit", "gpt-4o", 1000, 500)

        assert isinstance(entry, TokenUsage)
        assert entry.agent == "exploit"
        assert entry.model == "gpt-4o"
        assert entry.input_tokens == 1000
        assert entry.output_tokens == 500
        assert entry.total_tokens == 1500

    def test_totals_aggregate_across_calls(self):
        t = CostTracker()
        t.add("recon", "gpt-4o-mini", 200, 100)
        t.add("intel", "gpt-4o-mini", 800, 300)
        t.add("exploit", "gpt-4o", 1500, 700)

        assert t.call_count == 3
        assert t.total_input_tokens == 2500
        assert t.total_output_tokens == 1100
        assert t.total_tokens == 3600

    def test_by_agent_groups_correctly(self):
        t = CostTracker()
        t.add("intel", "gpt-4o-mini", 100, 50)
        t.add("intel", "gpt-4o-mini", 200, 80)
        t.add("exploit", "gpt-4o", 500, 200)

        by_agent = t.by_agent()
        assert set(by_agent.keys()) == {"intel", "exploit"}
        assert by_agent["intel"].total_tokens == 430
        assert by_agent["exploit"].total_tokens == 700

    def test_by_model_groups_correctly(self):
        t = CostTracker()
        t.add("intel", "gpt-4o-mini", 100, 50)
        t.add("exploit", "gpt-4o-mini", 200, 80)
        t.add("exploit", "claude-opus-4-7", 1000, 400)

        by_model = t.by_model()
        assert set(by_model.keys()) == {"gpt-4o-mini", "claude-opus-4-7"}
        assert by_model["gpt-4o-mini"].call_count == 2
        assert by_model["claude-opus-4-7"].call_count == 1

    def test_reset_clears_calls(self):
        t = CostTracker()
        t.add("recon", "gpt-4o", 100, 50)
        assert t.call_count == 1
        t.reset()
        assert t.call_count == 0
        assert t.total_tokens == 0
