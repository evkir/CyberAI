"""The retry helper must retry, must stop, and must re-raise what it caught.

cyberai/agents/intel/nvd_client.py calls exponential_backoff on every NVD
request, and until this file existed the helper had no test at all. Three
properties matter to the caller and none of them was held: that a call
which succeeds late is not reported as a failure, that a call which never
succeeds stops after max_retries rather than looping, and that the
exception the caller finally sees is the last real one rather than a
substitute.

Sleeping is patched out. A test that waited for the real delays would take
fourteen seconds at the helper's own defaults, and a slow test is a test
that gets marked slow and stops running.

The exceptions tuple is exercised with a type outside it. The helper
declares which failures are worth retrying, and a helper that retried
everything would pass the first two tests here while turning a typo in a
URL into five identical attempts.
"""

import pytest

from cyberai.utils.backoff import exponential_backoff


class _Boom(Exception):
    pass


class _Other(Exception):
    pass


def test_a_call_that_succeeds_on_the_last_attempt_is_not_a_failure(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _Boom("not yet")
        return "ok"

    assert exponential_backoff(flaky, max_retries=3, exceptions=(_Boom,)) == "ok"
    assert calls["n"] == 3


def test_the_helper_stops_after_max_retries(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    calls = {"n": 0}

    def always():
        calls["n"] += 1
        raise _Boom("never")

    with pytest.raises(_Boom):
        exponential_backoff(always, max_retries=4, exceptions=(_Boom,))
    assert calls["n"] == 4, "the ceiling is the number of attempts, not of sleeps"


def test_the_exception_the_caller_sees_is_the_last_one_raised(monkeypatch):
    """Not the first, and not a wrapper: the caller reads the final cause."""
    monkeypatch.setattr("time.sleep", lambda _: None)
    calls = {"n": 0}

    def numbered():
        calls["n"] += 1
        raise _Boom(f"attempt-{calls['n']}")

    with pytest.raises(_Boom, match="attempt-3"):
        exponential_backoff(numbered, max_retries=3, exceptions=(_Boom,))


def test_a_failure_outside_the_declared_set_is_not_retried(monkeypatch):
    """Control: a helper that retried everything passes the tests above."""
    monkeypatch.setattr("time.sleep", lambda _: None)
    calls = {"n": 0}

    def wrong_kind():
        calls["n"] += 1
        raise _Other("not for retrying")

    with pytest.raises(_Other):
        exponential_backoff(wrong_kind, max_retries=5, exceptions=(_Boom,))
    assert calls["n"] == 1, "a failure the caller did not name must travel at once"


def test_no_sleep_happens_after_the_last_attempt(monkeypatch):
    """A delay nobody waits through is a delay the caller pays for nothing."""
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", lambda d: slept.append(d))

    def always():
        raise _Boom("never")

    with pytest.raises(_Boom):
        exponential_backoff(always, max_retries=3, exceptions=(_Boom,))
    assert len(slept) == 2, slept
