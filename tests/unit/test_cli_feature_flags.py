"""CLI feature flags: tri-state semantics and precedence over the environment.

Every one of these flags gates a capability that is off by default, so a
silent wiring mistake does not fail anything -- it just means the feature
never runs and no test notices. The env-precedence cases matter most: the
bench builds its config with `from_env`, so a CLI flag that clobbered an
unset value would switch a capability off for runs that never passed a flag.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from cyberai.__main__ import _apply_feature_overrides, scan
from cyberai.core.config import CyberAIConfig

# (CLI keyword, config attribute, environment variable)
FLAGS = [
    ("web_recon", "use_web_recon", "CYBERAI_USE_WEB_RECON"),
    ("web_exploit", "use_web_exploit", "CYBERAI_USE_WEB_EXPLOIT"),
    ("api_discovery", "use_api_discovery", "CYBERAI_USE_API_DISCOVERY"),
    ("plan_web_order", "use_plan_web_order", "CYBERAI_USE_PLAN_WEB_ORDER"),
    ("planned_redteam", "use_planned_redteam", "CYBERAI_USE_PLANNED_REDTEAM"),
]

IDS = [f[0] for f in FLAGS]


@pytest.mark.parametrize("kw,attr,_env", FLAGS, ids=IDS)
def test_flag_forces_on(kw, attr, _env):
    cfg = _apply_feature_overrides(CyberAIConfig(), **{kw: True})
    assert getattr(cfg, attr) is True


@pytest.mark.parametrize("kw,attr,_env", FLAGS, ids=IDS)
def test_flag_forces_off(kw, attr, _env):
    cfg = CyberAIConfig()
    setattr(cfg, attr, True)
    assert getattr(_apply_feature_overrides(cfg, **{kw: False}), attr) is False


@pytest.mark.parametrize("kw,attr,_env", FLAGS, ids=IDS)
def test_flag_none_leaves_the_env_value(kw, attr, _env):
    cfg = CyberAIConfig()
    setattr(cfg, attr, True)
    assert getattr(_apply_feature_overrides(cfg, **{kw: None}), attr) is True


@pytest.mark.parametrize("kw,attr,env", FLAGS, ids=IDS)
def test_env_survives_when_no_flag_is_passed(kw, attr, env, monkeypatch):
    monkeypatch.setenv(env, "1")
    cfg = _apply_feature_overrides(CyberAIConfig.from_env())
    assert getattr(cfg, attr) is True


@pytest.mark.parametrize("kw,attr,env", FLAGS, ids=IDS)
def test_flag_overrides_the_env(kw, attr, env, monkeypatch):
    monkeypatch.setenv(env, "1")
    cfg = _apply_feature_overrides(CyberAIConfig.from_env(), **{kw: False})
    assert getattr(cfg, attr) is False


def test_overriding_one_flag_leaves_the_others_alone():
    cfg = _apply_feature_overrides(CyberAIConfig(), web_recon=True)
    assert cfg.use_web_recon is True
    assert cfg.use_web_exploit is False
    assert cfg.use_api_discovery is False
    assert cfg.use_plan_web_order is False
    assert cfg.use_planned_redteam is False


@pytest.mark.parametrize("kw,_attr,_env", FLAGS, ids=IDS)
def test_flag_pair_is_exposed_in_help(kw, _attr, _env):
    out = CliRunner().invoke(scan, ["--help"]).output
    name = kw.replace("_", "-")
    assert f"--{name}" in out
    assert f"--no-{name}" in out


def test_scan_accepts_every_new_flag(tmp_path, monkeypatch):
    """A flag the command signature forgot would fail here, not in the field."""
    monkeypatch.chdir(tmp_path)
    args = ["example.com", "--dry-run"]
    for kw, _attr, _env in FLAGS:
        args.append(f"--{kw.replace('_', '-')}")
    result = CliRunner().invoke(scan, args)
    assert result.exit_code == 0


WEB_PHASE_ATTRS = ("use_web_recon", "use_api_discovery", "use_web_exploit")


@pytest.mark.parametrize("target", ["http://t:5001", "https://t", "HTTP://T"])
def test_http_target_turns_the_web_phase_on(target):
    """A URL with the web phase off yields an empty report, not a clean one."""
    config = CyberAIConfig()
    _apply_feature_overrides(config, target=target)
    for attr in WEB_PHASE_ATTRS:
        assert getattr(config, attr) is True, attr


@pytest.mark.parametrize("target", ["example.com", "10.0.0.1", "scanme.nmap.org", ""])
def test_non_url_target_leaves_the_web_phase_alone(target):
    """Only the shape of the target decides; a host name is not a web target."""
    config = CyberAIConfig()
    _apply_feature_overrides(config, target=target)
    for attr in WEB_PHASE_ATTRS:
        assert getattr(config, attr) is False, attr


def test_explicit_flag_still_beats_the_url_default():
    """The default follows the target; an explicit choice overrides it."""
    config = CyberAIConfig()
    _apply_feature_overrides(config, target="http://t", web_exploit=False)
    assert config.use_web_recon is True
    assert config.use_api_discovery is True
    assert config.use_web_exploit is False


def test_target_defaults_to_empty_and_changes_nothing():
    """Callers that pass no target keep the previous behaviour exactly."""
    config = CyberAIConfig()
    _apply_feature_overrides(config)
    for attr in WEB_PHASE_ATTRS:
        assert getattr(config, attr) is False, attr
