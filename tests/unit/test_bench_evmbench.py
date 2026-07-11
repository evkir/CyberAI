"""
EVMBench loader + detect-mode grader contract tests.

Proves the format adapter and the deterministic recall grader hold together
without any external toolchain: a synthetic two-vulnerability audit fixture is
loaded into BenchTasks, and a mocked detect submission is graded per known
vulnerability. No Docker, no Foundry, no network.
"""

from __future__ import annotations

from pathlib import Path

from cyberai.bench.evmbench_loader import (
    EVMBenchAdapter,
    EVMBenchAudit,
    EVMBenchVuln,
    classify_title,
    grade_detect,
    load_audit,
)
from cyberai.bench.runner import BenchTask, SuiteReport
from cyberai.bench.scorecard import RunMeta, generate_scorecard

_FIXTURE_ROOT = Path(__file__).parent.parent / "bench" / "fixtures" / "evmbench"
_SYNTHETIC = _FIXTURE_ROOT / "synthetic-vault"


# --- classify_title --------------------------------------------------------


def test_classify_title_known_classes():
    assert classify_title("Reentrancy in withdraw drains vault") == "reentrancy"
    assert classify_title("Unauthorized access to setOwner") == "access-control"
    assert classify_title("Integer overflow in reward math") == "arithmetic"
    assert classify_title("Price oracle manipulation via flash loan") == "price-oracle"
    assert classify_title("delegatecall to attacker contract") == "delegatecall"


def test_classify_title_regex_branch():
    # "missing.*check" is a regex pattern, matched via re.search, mapping to
    # access-control when a title has "missing ... check".
    assert classify_title("Missing owner check on withdraw") == "access-control"


def test_classify_title_unknown_when_no_keyword():
    assert classify_title("A completely novel and undescribed issue") == "unknown"
    assert classify_title("") == "unknown"


def test_classify_title_first_keyword_wins():
    # "reentran" appears before generic loss-of-funds terms, so a reentrancy
    # title that also mentions draining classifies as reentrancy, not funds.
    assert classify_title("Reentrancy lets attacker drain funds") == "reentrancy"


# --- loading ---------------------------------------------------------------


def test_load_audit_parses_synthetic_fixture():
    audit = load_audit(_SYNTHETIC)
    assert audit is not None
    assert audit.id == "synthetic-vault"
    assert audit.framework == "foundry"
    assert audit.base_commit == "4240445ed3b5145be1032cf1becc9c6866046bf7"
    assert len(audit.vulnerabilities) == 2

    by_id = {v.id: v for v in audit.vulnerabilities}
    assert by_id["H-01"].vuln_class == "reentrancy"
    assert by_id["H-01"].award == 1500.0
    assert by_id["H-01"].exploit_task is True
    assert by_id["H-02"].vuln_class == "access-control"
    assert by_id["H-02"].award == 0.0
    assert by_id["H-02"].exploit_task is False


def test_detect_max_award_sums_vuln_awards():
    audit = load_audit(_SYNTHETIC)
    assert audit is not None
    assert audit.detect_max_award == 1500.0


def test_load_audit_missing_config_returns_none(tmp_path):
    assert load_audit(tmp_path) is None


def test_load_audit_bad_yaml_returns_none(tmp_path):
    (tmp_path / "config.yaml").write_text("id: x\n  bad: : indent")
    assert load_audit(tmp_path) is None


def test_load_audit_no_id_returns_none(tmp_path):
    (tmp_path / "config.yaml").write_text("vulnerabilities:\n  - id: H-01\n    title: t\n")
    assert load_audit(tmp_path) is None


def test_load_audit_no_vulnerabilities_returns_none(tmp_path):
    (tmp_path / "config.yaml").write_text("id: empty\nvulnerabilities: []\n")
    assert load_audit(tmp_path) is None


def test_load_audit_skips_malformed_vuln_keeps_valid(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "id: mixed\n"
        "vulnerabilities:\n"
        '  - id: "H-01"\n'
        '    title: "Reentrancy drain"\n'
        "  - award: 5.0\n"  # missing id + title -> skipped
    )
    audit = load_audit(tmp_path)
    assert audit is not None
    assert [v.id for v in audit.vulnerabilities] == ["H-01"]


def test_load_audit_all_vulns_malformed_returns_none(tmp_path):
    # every vuln lacks required keys -> no valid vuln -> whole audit is None
    (tmp_path / "config.yaml").write_text(
        "id: allbad\nvulnerabilities:\n  - award: 1.0\n  - exploit_task: true\n"
    )
    assert load_audit(tmp_path) is None


def test_load_audit_single_vuln_dict_normalized(tmp_path):
    # A single mapping instead of a list is accepted and wrapped.
    (tmp_path / "config.yaml").write_text(
        'id: single\nvulnerabilities:\n  id: "H-01"\n  title: "Reentrancy"\n'
    )
    audit = load_audit(tmp_path)
    assert audit is not None
    assert len(audit.vulnerabilities) == 1


def test_load_audit_award_non_numeric_defaults_zero(tmp_path):
    (tmp_path / "config.yaml").write_text(
        'id: badaward\nvulnerabilities:\n  - id: "H-01"\n    title: "t"\n    award: "N/A"\n'
    )
    audit = load_audit(tmp_path)
    assert audit is not None
    assert audit.vulnerabilities[0].award == 0.0


# --- adapter ---------------------------------------------------------------


def test_adapter_none_root_empty_suite():
    assert EVMBenchAdapter(None).load_tasks() == []


def test_adapter_missing_root_empty_suite(tmp_path):
    assert EVMBenchAdapter(tmp_path / "nope").load_tasks() == []


def test_adapter_loads_fixture_as_bench_tasks():
    adapter = EVMBenchAdapter(_FIXTURE_ROOT)
    tasks = adapter.load_tasks()
    assert len(tasks) == 1
    task = tasks[0]
    assert isinstance(task, BenchTask)
    assert task.id == "synthetic-vault"
    assert task.suite == "evmbench"
    assert task.metadata["mode"] == "detect"
    assert task.metadata["framework"] == "foundry"
    assert task.metadata["vuln_ids"] == ["H-01", "H-02"]
    assert task.metadata["detect_max_award"] == 1500.0


def test_bench_task_does_not_leak_ground_truth():
    task = EVMBenchAdapter(_FIXTURE_ROOT).load_tasks()[0]
    # neither the reference titles nor the vuln descriptions appear in the goal
    assert "reentran" not in task.success_criteria.lower()
    assert "setowner" not in task.success_criteria.lower()


def test_adapter_get_audit_resolves_ground_truth():
    adapter = EVMBenchAdapter(_FIXTURE_ROOT)
    audit = adapter.get_audit("synthetic-vault")
    assert isinstance(audit, EVMBenchAudit)
    assert adapter.get_audit("does-not-exist") is None


# --- detect grading --------------------------------------------------------


def _audit() -> EVMBenchAudit:
    audit = load_audit(_SYNTHETIC)
    assert audit is not None
    return audit


def test_grade_detect_full_submission_detects_all():
    submission = {
        "vulnerabilities": [
            {"title": "Reentrancy allows draining the vault"},
            {"title": "Unauthorized ownership takeover", "impact": "anyone can seize owner"},
        ]
    }
    results = grade_detect(_audit(), submission)
    assert len(results) == 2
    assert all(r.solved for r in results)
    assert {r.details["vuln_class"] for r in results} == {"reentrancy", "access-control"}
    assert all(r.task_id.startswith("synthetic-vault:") for r in results)


def test_grade_detect_partial_submission():
    submission = {"vulnerabilities": [{"title": "reentrancy drain"}]}
    results = grade_detect(_audit(), submission)
    solved = [r for r in results if r.solved]
    assert len(solved) == 1
    assert solved[0].details["vuln_class"] == "reentrancy"


def test_grade_detect_empty_submission_detects_nothing():
    results = grade_detect(_audit(), {"vulnerabilities": []})
    assert not any(r.solved for r in results)


def test_grade_detect_malformed_submission_detects_nothing():
    assert not any(r.solved for r in grade_detect(_audit(), {}))
    assert not any(r.solved for r in grade_detect(_audit(), {"vulnerabilities": "nope"}))
    assert not any(r.solved for r in grade_detect(_audit(), {"vulnerabilities": [42, None]}))


def test_grade_detect_consume_prevents_double_scoring():
    # Two reentrancy reports; only one known reentrancy vuln (H-01). H-02 is
    # access-control and must stay unsolved -> exactly one solved.
    submission = {"vulnerabilities": [{"title": "reentrancy"}, {"title": "reentrancy again"}]}
    results = grade_detect(_audit(), submission)
    assert sum(r.solved for r in results) == 1


def test_grade_detect_unknown_class_needs_unknown_report():
    audit = EVMBenchAudit(
        id="u",
        vulnerabilities=(EVMBenchVuln(id="X-1", title="an utterly opaque bug"),),
        source_dir="/tmp/u",
    )
    # a real-class report must not match the unknown ground-truth vuln
    assert not grade_detect(audit, {"vulnerabilities": [{"title": "reentrancy"}]})[0].solved
    # an unknown-class report does match
    assert grade_detect(audit, {"vulnerabilities": [{"title": "also opaque"}]})[0].solved


def test_grade_detect_feeds_scorecard_per_class():
    results = grade_detect(
        _audit(),
        {"vulnerabilities": [{"title": "reentrancy drain"}, {"title": "unauthorized owner"}]},
    )
    report = SuiteReport(
        suite="evmbench",
        total=len(results),
        solved=sum(r.solved for r in results),
        results=tuple(results),
    )
    md = generate_scorecard(report, RunMeta(model="test", provider="deterministic"))
    assert "reentrancy" in md
    assert "access-control" in md
    assert "2/2" in md
