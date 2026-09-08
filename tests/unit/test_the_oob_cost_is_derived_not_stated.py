"""What the out-of-band path costs is computed from the corpus that runs.

The bench profile documented the cost as three parameters times a five
second wait: fifteen seconds a task. Measured 2026-09-08 against VAmPI with
three blind parameters, the walk took roughly four minutes -- 10:12:59 to
10:17:54 -- because the wait is charged after every delivery, not once per
parameter, and a run sends the base corpus and then its mutations.

An estimate typed into a comment cannot notice the corpus growing. This one
is derived from the same payload generators the delivery loop reads, so the
day a category gains payloads the bound moves with it.
"""

from __future__ import annotations

from pathlib import Path

from cyberai.agents.exploit.oob_workflow import OOBWorkflow, worst_case_wait_seconds
from cyberai.integrations.oob_payloads import get_all_payloads, mutate_payloads


def test_the_bound_counts_the_mutation_batch_too():
    """The retry round is half the corpus and was absent from the estimate."""
    base = get_all_payloads("grid.invalid", "0" * 8)["ssrf"]
    base_only = len(base) * 5.0 * 3

    assert worst_case_wait_seconds("ssrf", max_wait=5.0, max_params=3) > base_only


def test_the_bound_refutes_the_number_it_replaces():
    """15s was the claim; nothing in the corpus supports it."""
    assert worst_case_wait_seconds("ssrf", max_wait=5.0, max_params=3) > 15.0


def test_the_bound_scales_with_both_knobs():
    one = worst_case_wait_seconds("cmdi", max_wait=5.0, max_params=1)
    three = worst_case_wait_seconds("cmdi", max_wait=5.0, max_params=3)
    slow = worst_case_wait_seconds("cmdi", max_wait=10.0, max_params=1)

    assert three == one * 3
    assert slow == one * 2


def test_an_unknown_category_costs_nothing_rather_than_guessing():
    assert worst_case_wait_seconds("no-such-class", max_wait=5.0, max_params=3) == 0.0


class _NeverCallsBack:
    def __init__(self):
        self.waits = 0

    def wait_for_callback(self, token):
        self.waits += 1
        return None


def test_the_wait_is_charged_per_delivery():
    """The mechanism behind the number, pinned separately from the number.

    If the poller were consulted once per parameter, the old estimate would
    have been right. It is consulted once per payload.
    """
    poller = _NeverCallsBack()
    workflow = OOBWorkflow(poller=poller)
    payloads = [{"type": "t", "payload": f"p{i}"} for i in range(4)]

    result = workflow._deliver_batch(payloads, "tok", lambda p: None, [], "ssrf", "ssrf")

    assert result is None
    assert poller.waits == 4


def test_the_bench_comment_cites_the_helper_rather_than_a_number():
    """A derived bound stops being derived the moment someone types it back."""
    repo = Path(__file__).resolve().parents[2]
    source = (repo / "cyberai" / "bench" / "agent_engine.py").read_text()

    assert "worst_case_wait_seconds" in source
    assert "at most 15s" not in source


def test_the_mutation_batch_is_not_empty_for_the_blind_class():
    """Guards the test above: a bound that counted nothing would still pass."""
    base = get_all_payloads("grid.invalid", "0" * 8)["ssrf"]
    assert len(mutate_payloads(base)) > 0
