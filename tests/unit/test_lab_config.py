"""Config defaults for the lab-dogfood feature."""

from __future__ import annotations

from cyberai.core.config import CyberAIConfig


def test_lab_flags_default_off() -> None:
    cfg = CyberAIConfig()
    assert cfg.use_lab_dogfood is False
    assert cfg.lab_flag_patterns == []


def test_lab_flag_patterns_independent_per_instance() -> None:
    # default_factory must give each config its own list, not a shared one.
    a = CyberAIConfig()
    a.lab_flag_patterns.append(r"CTF\{.*\}")
    b = CyberAIConfig()
    assert b.lab_flag_patterns == []
