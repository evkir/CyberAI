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
