"""Both scope gates compare the same key.

Measured on 2026-09-08 against a live run: `scan http://127.0.0.1:3000
--scope 127.0.0.1` reported a clean pass while web exploitation never ran.
The orchestrator gate reduces the target to a bare host before matching;
the in-agent guard matched the raw string, so `http://127.0.0.1:3000` was
compared against `127.0.0.1` and missed. Web exploitation was unreachable
for every URL target under every scope value: a host entry passed the
orchestrator and was refused by the agent, a URL entry was refused by the
orchestrator, and an empty scope only worked where the protected-IP check
did not fire.

The normalisation belongs on the target, never on the scope entry:
_target_host("10.0.0.0/8") is "10.0.0.0" -- urlparse reads /8 as a path --
so normalising entries would silently turn every CIDR into a single host.
"""

from unittest.mock import MagicMock, patch

import pytest

from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.agents.exploit.safety_validator import validate_exploit_scope
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


def _agent(scope, target="http://10.10.10.5:3000"):
    session = ScanSession(target=target, authorized_scope=scope)
    return ExploitAgent(CyberAIConfig(), session)


@pytest.mark.parametrize(
    "target,scope",
    [
        ("http://10.10.10.5:3000", ["10.10.10.5"]),
        ("http://10.10.10.5:3000", ["10.10.10.0/24"]),
        ("https://sub.acme.com:8443/app?x=1", ["*.acme.com"]),
    ],
)
def test_a_url_target_matches_a_host_scope_entry(target, scope):
    assert _agent(scope)._scope_ok(target) is True


@pytest.mark.parametrize(
    "target,scope",
    [
        ("http://evil.example.com/x", ["*.acme.com"]),
        ("http://11.0.0.5:80", ["10.0.0.0/8"]),
    ],
)
def test_a_url_target_outside_the_scope_is_still_blocked(target, scope):
    assert _agent(scope)._scope_ok(target) is False


def test_a_cidr_entry_keeps_its_prefix():
    """The entry side is never normalised.

    Reducing "10.0.0.0/8" to a host would admit 10.0.0.0 alone and refuse
    every other address the operator authorised.
    """
    guard = _agent(["10.0.0.0/8"])
    assert guard._scope_ok("http://10.0.0.5:3000") is True
    assert guard._scope_ok("http://10.255.255.254") is True


_PARITY_CASES = [
    ("http://10.10.10.5:3000", ["10.10.10.5"]),
    ("http://10.10.10.5:3000", ["10.10.10.0/24"]),
    ("https://sub.acme.com:8443/app", ["*.acme.com"]),
    ("http://evil.example.com", ["*.acme.com"]),
    ("scanme.nmap.org", ["scanme.nmap.org"]),
]


@pytest.mark.parametrize("target,scope", _PARITY_CASES)
def test_both_gates_reach_the_same_verdict(target, scope):
    """The orchestrator and the agent must not disagree about one value.

    Either verdict alone is defensible; a split between them is what made a
    refusal look like a clean scan for six weeks.
    """
    orchestrator = validate_exploit_scope(target, scope).passed
    assert _agent(scope)._scope_ok(target) is orchestrator


_SURFACE = {
    "endpoints": [
        {
            "method": "GET",
            "url": "http://10.10.10.5:3000/search",
            "params": ["q"],
        }
    ]
}


def test_the_walk_runs_for_a_url_target_the_operator_authorised_by_host():
    """The production form of the argument, not the tested one.

    Every existing guard test passes _scope_ok a bare hostname. The pipeline
    passes it the URL it was invoked with, which is why 2681 green tests sat
    on top of a dead exploit path.
    """
    agent = _agent(["10.10.10.5"])
    agent.kb.set("recon.web_surface", _SURFACE)

    report = MagicMock()
    report.findings = []
    report.oob_confirmed_params = []
    report.params_oob_confirmed = 0
    report.to_dict.return_value = {"confirmed": 0, "endpoints_tested": 1, "findings": []}

    with patch("cyberai.agents.exploit.agent.exploit_surface", return_value=report) as walk:
        agent._run_web_exploit("http://10.10.10.5:3000")

    walk.assert_called_once()
