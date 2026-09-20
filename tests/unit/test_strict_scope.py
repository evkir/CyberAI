"""An empty scope refuses the exploit phase unless the run says otherwise.

T3 in STANDOFF-KEY, and risk 20 in the register. The validator warned on an
absent scope and let the run proceed. Absence of authorisation is not
authorisation, so 1.7.0 inverts it: the refusal is the default and the run
that wants to proceed anyway says so with --no-strict-scope.

Until 1.7.0 this file argued the opposite, that a flag altering behaviour
for people who did not set it is a surprise rather than a safety feature.
The argument was sound about surprise and wrong about which way it points:
for a tool that attacks things, the surprising default is the one that
proceeds against a target nobody named. What the argument did buy was an
inventory -- measured before the flip, exactly five tests depended on the
old default, four of them because they drove the exploit phase without ever
saying what they were allowed to touch. Those now say it.

The chain is tested end to end rather than at the validator alone, because
each link has failed independently before: a flag declared in click and never
read, a config field with no consumer, an orchestrator that computes a
verdict and ignores it. Here the CLI option reaches the config, the config
reaches the validator, and the orchestrator turns the violation into a
failed phase.
"""

import pytest

from cyberai.agents.exploit.safety_validator import validate_exploit_scope
from cyberai.core.config import CyberAIConfig, _env_bool, _env_guard_bool


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


def test_config_field_defaults_on_and_reads_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default moved in 1.7.0, and the environment can still refuse it.

    Both directions are asserted because a default that cannot be turned off
    is not a default, it is a wall, and the run that knows what it is doing
    -- a lab with no scope file, a rehearsal against a host the operator owns
    -- has to be able to say so without editing code.
    """
    monkeypatch.delenv("CYBERAI_STRICT_SCOPE", raising=False)
    assert CyberAIConfig.from_env().strict_scope is True
    monkeypatch.setenv("CYBERAI_STRICT_SCOPE", "0")
    assert CyberAIConfig.from_env().strict_scope is False


def test_only_a_named_word_turns_the_refusal_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo is not consent.

    _env_bool reads every value outside its truthy set as false, which is the
    right answer for a flag that defaults to off -- an unrecognised value
    lands where the default already was. This flag defaults to on, so the
    same rule handed the refusal to anything at all: measured on 2026-09-19,
    CYBERAI_STRICT_SCOPE= turned it off, and so did CYBERAI_STRICT_SCOPE=nope.
    An empty variable is what a shell leaves behind for VAR= in a .env file
    or VAR=$MISSING in a script, so this was reachable without anyone
    deciding anything.

    The README table and risk 20 both name the ways to proceed without a
    scope: `0` and --no-strict-scope. This asserts that list and no more.
    """
    for word in ("0", "false", "no", "off", "OFF", " 0 "):
        monkeypatch.setenv("CYBERAI_STRICT_SCOPE", word)
        assert CyberAIConfig.from_env().strict_scope is False, word

    for noise in ("", " ", "nope", "flase", "2", "null", "none"):
        monkeypatch.setenv("CYBERAI_STRICT_SCOPE", noise)
        assert CyberAIConfig.from_env().strict_scope is True, noise

    # Saying yes out loud is a third answer, not the absence of the other two.
    # Coverage caught this branch unexecuted: every assertion above lands on
    # off or on the default, so a reader that never recognised a word for yes
    # would have passed them all. An operator who writes the variable to turn
    # the guard back on has to be answered.
    for word in ("1", "true", "yes", "on", "ON", " 1 "):
        monkeypatch.setenv("CYBERAI_STRICT_SCOPE", word)
        assert CyberAIConfig.from_env().strict_scope is True, word


def test_the_ordinary_flag_reader_is_left_as_it_was(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard reader is for guards; the other twenty-two keep their reader.

    Changing _env_bool itself would have rewritten the meaning of every flag
    in the file to fix one of them. For a flag defaulting to off the two
    readers cannot disagree, but the distinction is the point, so it is
    stated here rather than left to be rediscovered.
    """
    monkeypatch.setenv("CYBERAI_TEST_FLAG", "nope")
    assert _env_bool("CYBERAI_TEST_FLAG", True) is False
    assert _env_guard_bool("CYBERAI_TEST_FLAG", True) is True

    # Asserted against a default of False, which is the only way this says
    # anything. strict_scope defaults to True, so a reader that recognised no
    # word for yes would answer True for "1" by falling through to the
    # default and every assertion about that flag would still pass -- the
    # branch was covered and unproven at once. Here the two answers differ.
    for word in ("1", "true", "yes", "on"):
        monkeypatch.setenv("CYBERAI_TEST_FLAG", word)
        assert _env_guard_bool("CYBERAI_TEST_FLAG", False) is True, word
    for word in ("0", "false", "no", "off"):
        monkeypatch.setenv("CYBERAI_TEST_FLAG", word)
        assert _env_guard_bool("CYBERAI_TEST_FLAG", True) is False, word


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
    """--no-strict-scope is how a run opts out, and it beats the environment.

    The last assertion is the one that matters: passing None leaves the value
    alone rather than reinstating a default. A flag that resets what it was
    not given would turn every unrelated CLI call into a policy change.
    """
    from cyberai.__main__ import _apply_feature_overrides

    monkeypatch.setenv("CYBERAI_STRICT_SCOPE", "0")
    config = CyberAIConfig.from_env()
    assert config.strict_scope is False
    assert _apply_feature_overrides(config, strict_scope=True).strict_scope is True
    assert _apply_feature_overrides(config, strict_scope=None).strict_scope is True


def test_the_library_default_and_the_product_default_are_different_questions() -> None:
    """The flip moved the product answer, not the function signature.

    validate_exploit_scope still warns when called without strict, because a
    caller reaching it directly has already decided what it wants; the
    orchestrator is the one that carries policy, and it reads the config. If
    the two ever collapse into one, a direct call site silently inherits a
    refusal it never asked for, and the flag stops being something a run can
    answer for itself.
    """
    lenient = validate_exploit_scope("scanme.nmap.org", [], [])
    assert lenient.passed
    assert CyberAIConfig().strict_scope is True


def test_a_scoped_run_is_untouched_by_the_flip() -> None:
    """The change costs nothing to a run that named its scope.

    This is the claim the CHANGELOG makes to a reader deciding whether to
    upgrade, so it is asserted rather than promised: with a scope present,
    the verdict under the new default matches the old one exactly.
    """
    before = validate_exploit_scope("scanme.nmap.org", ["scanme.nmap.org"], [], strict=False)
    after = validate_exploit_scope("scanme.nmap.org", ["scanme.nmap.org"], [], strict=True)
    assert before.passed and after.passed
    assert before.violations == after.violations
    assert before.warnings == after.warnings
