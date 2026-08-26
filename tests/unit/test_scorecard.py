"""Tests for the bench scorecard generator."""

from __future__ import annotations

from cyberai.bench.runner import BenchResult, SuiteReport
from cyberai.bench.scorecard import RunMeta, generate_scorecard


def _report() -> SuiteReport:
    results = (
        BenchResult("a", "local", True, 1.2, details={"vuln_class": "sqli"}),
        BenchResult("b", "local", False, 0.5, details={"vuln_class": "command_injection"}),
        BenchResult("c", "local", True, 2.0, details={"vuln_class": "sqli"}),
    )
    return SuiteReport(suite="local", total=3, solved=2, results=results)


def test_scorecard_headline_pass_at_1():
    md = generate_scorecard(_report())
    assert "pass@1: 2/3" in md
    assert "66.7%" in md


def test_scorecard_per_class_breakdown():
    md = generate_scorecard(_report())
    # sqli 2/2, command_injection 0/1
    assert "| sqli | 2 | 2 |" in md
    assert "| command_injection | 0 | 1 |" in md


def test_scorecard_per_task_rows():
    md = generate_scorecard(_report())
    assert "| a | ✓ |" in md
    assert "| b | ✗ |" in md


def test_scorecard_includes_run_meta():
    md = generate_scorecard(_report(), RunMeta(model="claude-opus", provider="anthropic"))
    assert "claude-opus" in md
    assert "anthropic" in md
    assert "CyberAI" in md


def test_scorecard_empty_suite():
    md = generate_scorecard(SuiteReport(suite="local", total=0, solved=0))
    assert "pass@1: 0/0 = 0.0%" in md


def _metric_report() -> SuiteReport:
    """One measured task, one that never came up, one that never said."""
    results = (
        BenchResult(
            "up",
            "cve-bench",
            True,
            3.0,
            details={
                "available": True,
                "agent_confirmed": 0,
                "oob_confirmed": 1,
                "endpoints_tested": 19,
                "requests_sent": 153,
            },
        ),
        BenchResult(
            "down",
            "cve-bench",
            False,
            0.1,
            error="task did not come up",
            details={"available": False},
        ),
        BenchResult(
            "quiet",
            "cve-bench",
            False,
            2.0,
            details={
                "agent_confirmed": 2,
                "oob_confirmed": 0,
                "endpoints_tested": 7,
                "requests_sent": 40,
            },
        ),
    )
    return SuiteReport("cve-bench", 3, 1, results)


def test_run_metrics_section_renders_measured_task():
    md = generate_scorecard(_metric_report())
    assert "## Run metrics" in md
    assert "| task id | available | in-band | out of band | endpoints | requests |" in md
    assert "| up | \u2713 | 0 | 1 | 19 | 153 |" in md


def test_run_metrics_section_absent_when_nothing_measured():
    """The `real` engine and EVMBench write no surface keys: no empty section."""
    md = generate_scorecard(_report())
    assert "## Run metrics" not in md


def test_availability_tells_absent_apart_from_false():
    """Not up, and never reported, are different facts in the artefact."""
    md = generate_scorecard(_metric_report())
    assert "| down | \u2717 | \u2014 | \u2014 | \u2014 | \u2014 |" in md
    assert "| quiet | ? | 2 | 0 | 7 | 40 |" in md


def test_a_target_that_never_came_up_still_gets_the_availability_column():
    """A task refused before it started measures nothing, so the metrics keyed
    the section out and the artefact read like an agent that searched and
    found nothing. The refusal is the reader's answer, not the surface."""
    results = (
        BenchResult(
            "clash",
            "cve-bench",
            False,
            0.08,
            error="task did not come up",
            details={"engine": "agent", "available": False},
        ),
    )
    md = generate_scorecard(SuiteReport(suite="cve-bench", total=1, solved=0, results=results))
    assert "## Run metrics" in md
    assert "| clash | \u2717 | \u2014 | \u2014 | \u2014 | \u2014 |" in md
    assert "| **total** | 0/1 | 0 | 0 | 0 | 0 |" in md


def test_a_probe_engine_that_measures_nothing_gets_no_section():
    """The probe engine records every target as up and measures none of them.
    Keying the section on availability alone turned that into a wall of
    dashes across the whole suite -- the shape this section exists to avoid."""
    results = (
        BenchResult("a", "local", True, 1.2, details={"vuln_class": "sqli", "available": True}),
        BenchResult("b", "local", True, 1.3, details={"vuln_class": "ssrf", "available": True}),
    )
    md = generate_scorecard(SuiteReport(suite="local", total=2, solved=2, results=results))
    assert "## Run metrics" not in md


def test_totals_row_counts_only_what_was_measured():
    md = generate_scorecard(_metric_report())
    assert "| **total** | 1/3 | 2 | 1 | 26 | 193 |" in md


def test_out_of_band_proof_is_not_folded_into_the_in_band_count():
    """A blind vector proves itself off the wire; solved with zero in-band
    proofs is the shape that once made a log line read as `nothing found`."""
    md = generate_scorecard(_metric_report())
    row = [ln for ln in md.splitlines() if ln.startswith("| up |")][0]
    assert row.split("|")[3].strip() == "0"
    assert row.split("|")[4].strip() == "1"


def test_a_run_that_named_no_model_leaves_the_rows_out():
    """A placeholder in a machine-readable table reads as a chosen value.
    The probe engine contacts nothing, and `unspecified` published that as
    if a model had been involved."""
    md = generate_scorecard(_report())
    assert "| model |" not in md
    assert "| provider |" not in md
    assert "unspecified" not in md


def test_the_version_row_no_longer_shares_a_key_with_the_engine_name():
    """The CLI writes `engine` to name the engine that ran, so the version
    under the same key gave one card two rows with one meaning between
    them."""
    md = generate_scorecard(_report(), RunMeta(extra={"engine": "agent"}))
    keys = [ln.split("|")[1].strip() for ln in md.splitlines() if ln.startswith("| ")]
    assert "engine version" in keys
    assert keys.count("engine") == 1


def test_a_proven_zero_and_its_cause_reach_the_card():
    md = generate_scorecard(_report(), RunMeta(llm_calls=0, llm_zero_reason="engine_uses_no_model"))
    assert "| llm calls | 0 |" in md
    assert "| llm zero reason | engine_uses_no_model |" in md


def test_an_unmeasured_run_writes_no_call_row_at_all():
    """Zero is a measurement. A run with nothing to count must not print one."""
    md = generate_scorecard(_report())
    assert "| llm calls |" not in md


def test_two_rows_under_one_key_are_refused():
    """Rendering both is how a machine-readable card starts carrying two
    truths; the second writer has to fail loudly instead."""
    import pytest

    with pytest.raises(ValueError, match="duplicate scorecard metadata key"):
        generate_scorecard(_report(), RunMeta(note="run", extra={"note": "other"}))
