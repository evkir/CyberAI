"""An empty scope refuses the exploit phase when the caller asked it to.

T3 in STANDOFF-KEY. The validator warned on an absent scope and let the run
proceed, which is defensible as a default -- the pipeline has always behaved
that way -- and indefensible as the only option. Absence of authorisation is
not authorisation, and an engagement where that distinction matters had no
way to say so.

The default is deliberately unchanged. Eighteen existing call sites pass no
strict argument and every one of them still gets a warning; a flag that
alters behaviour for people who did not set it is a surprise, not a safety
feature.

The chain is tested end to end rather than at the validator alone, because
each link has failed independently before: a flag declared in click and never
read, a config field with no consumer, an orchestrator that computes a
verdict and ignores it. Here the CLI option reaches the config, the config
reaches the validator, and the orchestrator turns the violation into a
failed phase.
"""

import pytest

from cyberai.agents.exploit.safety_validator import validate_exploit_scope
from cyberai.core.config import CyberAIConfig


def test_empty_scope_warns_by_default() -> None:
    v = validate_exploit_scope("scanme.nmap.org", [], [])
    assert v.passed
    assert any("proceeding without scope check" in w for w in v.warnings)
    assert not v.violations


def test_empty_scope_is_a_violation_under_strict() -> None:
    v = validate_exploit_scope("scanme.nmap.org", [], [], strict=True)
    assert not v.passed
    assert any("strict-scope" in x for x in v.violations)
    assert not any("proceeding without scope check" in w for w in v.warnings)


def test_strict_does_not_touch_a_run_that_has_a_scope() -> None:
    lenient = validate_exploit_scope("scanme.nmap.org", ["scanme.nmap.org"], [])
    strict = validate_exploit_scope("scanme.nmap.org", ["scanme.nmap.org"], [], strict=True)
    assert lenient.passed and strict.passed
    assert strict.violations == lenient.violations
    assert strict.warnings == lenient.warnings


def test_strict_does_not_rescue_an_out_of_scope_target() -> None:
    """A named scope the target misses already fails; strict changes nothing."""
    v = validate_exploit_scope("evil.example.com", ["scanme.nmap.org"], [], strict=True)
    assert not v.passed
    assert any("NOT in authorized scope" in x for x in v.violations)


def test_config_field_defaults_off_and_reads_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CYBERAI_STRICT_SCOPE", raising=False)
    assert CyberAIConfig.from_env().strict_scope is False
    monkeypatch.setenv("CYBERAI_STRICT_SCOPE", "1")
    assert CyberAIConfig.from_env().strict_scope is True


def test_the_orchestrator_hands_the_flag_to_the_validator() -> None:
    """The link the other tests cannot see.

    Removing `strict=self.config.strict_scope` from _run_exploit left all six
    of the tests above green: they drive the validator directly and the CLI
    directly, and neither notices that the phase in between stopped passing
    the value on. A flag that reaches the config and dies there is the shape
    this project calls a producer without a consumer, and it survives review
    precisely because every piece has a test.

    So this drives the phase. Under strict with no scope the exploit phase
    must refuse; the same session without strict must get past the check.
    Reaching the agent is not the point and would need a network, so the
    second case asserts on what the validator decided rather than on a run.
    """
    from cyberai.core.orchestrator import Orchestrator
    from cyberai.core.scan_session import ScanSession

    config = CyberAIConfig()
    config.strict_scope = True
    orch = Orchestrator(config=config, dry_run=True)
    session = ScanSession(target="scanme.nmap.org", authorized_scope=[])

    with pytest.raises(RuntimeError, match="Scope check failed"):
        orch._run_exploit(session)

    config.strict_scope = False
    lenient = validate_exploit_scope(
        session.target, session.authorized_scope, [], strict=config.strict_scope
    )
    assert lenient.passed


def test_cli_flag_overrides_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    from cyberai.__main__ import _apply_feature_overrides

    monkeypatch.setenv("CYBERAI_STRICT_SCOPE", "1")
    config = CyberAIConfig.from_env()
    assert config.strict_scope is True
    assert _apply_feature_overrides(config, strict_scope=False).strict_scope is False
    assert _apply_feature_overrides(config, strict_scope=None).strict_scope is False
