"""The two LLM behaviour flags must be reachable.

Both were read via getattr(config, ..., False) by their consumers while no
such field existed, so neither could ever be turned on. These tests pin the
fields into existence and keep the env names attached to them.
"""

import pytest

from cyberai.core.config import CyberAIConfig

CONSUMED_FLAGS = [
    ("use_native_tools", "CYBERAI_USE_NATIVE_TOOLS"),
    ("use_llm_summary", "CYBERAI_USE_LLM_SUMMARY"),
]
IDS = [f[0] for f in CONSUMED_FLAGS]


@pytest.mark.parametrize("attr,_env", CONSUMED_FLAGS, ids=IDS)
def test_flag_is_a_real_field_defaulting_off(attr, _env):
    cfg = CyberAIConfig()
    assert getattr(cfg, attr) is False
    assert attr in cfg.__dataclass_fields__


@pytest.mark.parametrize("attr,env", CONSUMED_FLAGS, ids=IDS)
def test_env_var_turns_the_flag_on(attr, env, monkeypatch):
    monkeypatch.setenv(env, "true")
    cfg = CyberAIConfig.from_env()
    assert getattr(cfg, attr) is True


@pytest.mark.parametrize("attr,env", CONSUMED_FLAGS, ids=IDS)
def test_env_var_absent_leaves_the_flag_off(attr, env, monkeypatch):
    monkeypatch.delenv(env, raising=False)
    cfg = CyberAIConfig.from_env()
    assert getattr(cfg, attr) is False


def test_sampling_settings_are_reachable_from_the_environment(monkeypatch):
    """temperature and seed must be settable without editing code.

    temperature had lived as a dataclass default no caller could change:
    from_env did not read it and the CLI assigns only provider and model.
    A value nobody can set is the same defect as a value that never reaches
    the request. seed stays None when unset or unparseable, because that is
    a different answer from a chosen 0 and garbage in a variable must not
    abort a scan on startup.
    """
    for name in ("CYBERAI_TEMPERATURE", "CYBERAI_SEED"):
        monkeypatch.delenv(name, raising=False)
    unset = CyberAIConfig.from_env().llm

    monkeypatch.setenv("CYBERAI_TEMPERATURE", "0.9")
    monkeypatch.setenv("CYBERAI_SEED", "7")
    chosen = CyberAIConfig.from_env().llm

    monkeypatch.setenv("CYBERAI_TEMPERATURE", "junk")
    monkeypatch.setenv("CYBERAI_SEED", "junk")
    garbage = CyberAIConfig.from_env().llm

    observed = {
        "unset": (unset.temperature, unset.seed),
        "chosen": (chosen.temperature, chosen.seed),
        "garbage": (garbage.temperature, garbage.seed),
    }
    assert observed == {
        "unset": (0.2, None),
        "chosen": (0.9, 7),
        "garbage": (0.2, None),
    }
