"""CLI wiring for the planner phase: tri-state flag and plan summary line."""

from __future__ import annotations

from click.testing import CliRunner

from cyberai.__main__ import _apply_feature_overrides, _plan_summary, scan
from cyberai.core.config import CyberAIConfig
from cyberai.core.orchestrator import Orchestrator
from cyberai.core.scan_session import ScanSession


def test_planner_flag_forces_on():
    cfg = _apply_feature_overrides(CyberAIConfig(), planner=True)
    assert cfg.enable_planner is True


def test_planner_flag_forces_off():
    cfg = CyberAIConfig()
    cfg.enable_planner = True
    assert _apply_feature_overrides(cfg, planner=False).enable_planner is False


def test_planner_flag_none_leaves_value():
    cfg = CyberAIConfig()
    cfg.enable_planner = True
    assert _apply_feature_overrides(cfg, planner=None).enable_planner is True


def test_plan_summary_none_without_plan():
    assert _plan_summary(None) is None
    assert _plan_summary("not-a-dict") is None
    assert _plan_summary({"todo": "nope"}) is None
    assert _plan_summary({"todo": []}) is None
    assert _plan_summary({"todo": [None, 3]}) is None


def test_plan_summary_counts_actions():
    plan = {
        "todo": [
            {"action": "exploit"},
            {"action": "exploit"},
            {"action": "enumerate"},
            None,
        ]
    }
    assert _plan_summary(plan) == "Plan: 3 subtask(s) - 1 enumerate, 2 exploit"


def test_plan_summary_unknown_action():
    assert _plan_summary({"todo": [{"target": "x"}]}) == "Plan: 1 subtask(s) - 1 unknown"


def test_planner_flag_exposed_in_help():
    out = CliRunner().invoke(scan, ["--help"]).output
    assert "--planner" in out and "--no-planner" in out


def test_scan_dry_run_with_planner_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(scan, ["example.com", "--dry-run", "--planner"])
    assert result.exit_code == 0


def test_scan_prints_plan_summary(tmp_path, monkeypatch):
    """The summary line only prints when a plan actually reached the KB."""

    def fake_run(self, target, authorized_scope=None):
        session = ScanSession(target=target)
        session.kb_set("plan", {"todo": [{"action": "exploit", "target": "CVE-1"}]})
        session.complete()
        return session

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Orchestrator, "run", fake_run)
    result = CliRunner().invoke(scan, ["example.com", "--dry-run", "--planner"])
    assert result.exit_code == 0
    assert "Plan: 1 subtask(s)" in result.output
