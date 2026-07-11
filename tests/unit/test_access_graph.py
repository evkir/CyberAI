"""Tests for the lightweight Solidity access-control source model."""

from __future__ import annotations

from pathlib import Path

from cyberai.agents.web3.access_graph import (
    ContractModel,
    FunctionInfo,
    parse_contracts,
)

_VULN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    mapping(bytes32 => mapping(address => bool)) public roles;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function withdrawAll() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function getOwner() external view returns (address) {
        return owner;
    }

    function withRole(bytes32 r) external onlyRole(r) {
        owner = msg.sender;
    }
}

interface IThing {
    function ping() external returns (uint256);
}
"""

DAO = Path(__file__).parent.parent / "fixtures" / "dao_reentrant.sol"


def test_parses_contract_and_interface():
    models = parse_contracts(_VULN)
    names = [m.name for m in models]
    assert names == ["Vault", "IThing"]


def test_function_visibility_and_mutability():
    vault = parse_contracts(_VULN)[0]
    fns = {f.name: f for f in vault.functions}
    assert fns["setOwner"].visibility == "external"
    assert fns["getOwner"].mutability == "view"
    assert fns["getOwner"].is_externally_callable is True
    # returns(...) must not leak into modifiers.
    assert fns["getOwner"].modifiers == []


def test_modifier_names_without_args():
    vault = parse_contracts(_VULN)[0]
    fns = {f.name: f for f in vault.functions}
    assert fns["withdrawAll"].modifiers == ["onlyOwner"]
    # onlyRole(r) -> bare name only.
    assert fns["withRole"].modifiers == ["onlyRole"]
    assert vault.modifiers_defined == ["onlyOwner"]


def test_owner_and_role_state_detected():
    vault = parse_contracts(_VULN)[0]
    assert "owner" in vault.owner_vars
    assert vault.has_role_state is True


def test_interface_declaration_has_no_body():
    ithing = parse_contracts(_VULN)[1]
    ping = ithing.functions[0]
    assert ping.name == "ping"
    assert ping.body == ""


def test_nested_braces_do_not_break_body():
    src = """
    contract C {
        function f() external {
            (bool ok, ) = msg.sender.call{value: 1}("");
            require(ok);
        }
    }
    """
    c = parse_contracts(src)[0]
    assert len(c.functions) == 1
    assert "require(ok)" in c.functions[0].body


def test_dao_fixture_has_no_owner_state():
    dao = parse_contracts(DAO.read_text())[0]
    assert dao.name == "DAOReentrant"
    assert dao.owner_vars == []
    assert [f.name for f in dao.functions] == ["deposit", "withdraw", "balanceOf"]


def test_empty_and_malformed():
    assert parse_contracts("") == []
    # Contract with no closing brace: body still captured to end, no crash.
    m = parse_contracts("contract Broken { function a() external { ")
    assert m[0].name == "Broken"


def test_dataclasses_construct():
    f = FunctionInfo(name="x", visibility="public")
    assert f.mutability == "nonpayable"
    c = ContractModel(name="C")
    assert c.functions == [] and c.owner_vars == []


def test_non_modifier_keywords_ignored():
    # virtual/override are keywords, not modifiers.
    c = parse_contracts("contract C { function f() external virtual override {} }")[0]
    assert c.functions[0].modifiers == []


def test_function_with_unmatched_paren_skipped():
    # An unmatched '(' yields no match index -> the function is skipped.
    c = parse_contracts("contract C { function f( }")[0]
    assert c.name == "C"
    assert c.functions == []


def test_contract_keyword_without_brace_skipped():
    assert parse_contracts("contract Ghost") == []
