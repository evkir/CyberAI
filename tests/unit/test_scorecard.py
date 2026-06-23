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
