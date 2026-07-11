"""Tests for the heuristic access-control detectors."""

from __future__ import annotations

from pathlib import Path

from cyberai.agents.web3.access_control import (
    AccessFinding,
    analyze_source,
    detect_controlled_delegatecall,
    detect_missing_auth,
)
from cyberai.agents.web3.access_graph import parse_contracts
from cyberai.agents.web3.immunefi_severity import classify

FIXTURE = Path(__file__).parent.parent / "fixtures" / "access_control.sol"
DAO = Path(__file__).parent.parent / "fixtures" / "dao_reentrant.sol"


def _by_check(source):
    out = {}
    for f in analyze_source(source):
        out.setdefault(f.check, []).append(f)
    return out


def test_full_fixture_detects_all_four():
    found = _by_check(FIXTURE.read_text())
    fns = {f.function for group in found.values() for f in group}
    assert "setOwner" in fns
    assert "initialize" in fns
    assert "execute" in fns
    assert "mint" in fns


def test_setowner_is_critical():
    found = _by_check(FIXTURE.read_text())
    setowner = next(f for f in found["missing-auth"] if f.function == "setOwner")
    assert classify(setowner) == "Critical"


def test_mint_is_high_not_critical():
    found = _by_check(FIXTURE.read_text())
    mint = next(f for f in found["missing-auth"] if f.function == "mint")
    assert mint.impact == "Medium"
    assert classify(mint) == "High"


def test_initializer_and_delegatecall_critical():
    found = _by_check(FIXTURE.read_text())
    assert classify(found["unprotected-initializer"][0]) == "Critical"
    assert classify(found["controlled-delegatecall"][0]) == "Critical"


def test_guarded_and_view_functions_are_silent():
    fns = {f.function for f in analyze_source(FIXTURE.read_text())}
    assert "withdrawAll" not in fns  # onlyOwner modifier
    assert "setFeeGuarded" not in fns  # inline require guard
    assert "deposit" not in fns  # not privileged
    assert "getOwner" not in fns  # view


def test_no_false_positive_on_dao():
    assert analyze_source(DAO.read_text()) == []


def test_missing_auth_skips_internal_and_view():
    src = """
    contract C {
        address owner;
        function _setOwner(address o) internal { owner = o; }
        function getOwner() external view returns (address) { return owner; }
    }
    """
    model = parse_contracts(src)[0]
    assert detect_missing_auth(model) == []


def test_inline_reverse_guard_recognized():
    # owner == msg.sender (reversed) also counts as a guard.
    src = """
    contract C {
        address owner;
        function setOwner(address o) external {
            require(owner == msg.sender);
            owner = o;
        }
    }
    """
    assert detect_missing_auth(parse_contracts(src)[0]) == []


def test_hasrole_guard_recognized():
    src = """
    contract C {
        address admin;
        function setAdmin(address a) external {
            require(hasRole(ADMIN, msg.sender));
            admin = a;
        }
    }
    """
    assert detect_missing_auth(parse_contracts(src)[0]) == []


def test_initializer_modifier_is_safe():
    src = """
    contract C {
        address owner;
        function initialize(address o) external initializer { owner = o; }
    }
    """
    from cyberai.agents.web3.access_control import detect_unprotected_initializer

    assert detect_unprotected_initializer(parse_contracts(src)[0]) == []


def test_delegatecall_free_contract_clean():
    src = "contract C { function f() external { uint256 x = 1; } }"
    assert detect_controlled_delegatecall(parse_contracts(src)[0]) == []


def test_finding_to_dict_tags_source():
    f = AccessFinding(
        check="missing-auth",
        impact="High",
        confidence="High",
        description="x",
        contract="C",
        function="setOwner",
    )
    d = f.to_dict()
    assert d["source"] == "access-control"
    assert d["check"] == "missing-auth"
    assert d["function"] == "setOwner"
