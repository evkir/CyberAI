"""Findings are classified into report domains by originating agent."""

from __future__ import annotations

from types import SimpleNamespace

from cyberai.agents.report.domains import (
    DOMAIN_ORDER,
    MCP,
    NETWORK,
    WEB3,
    domain_for,
    group_by_domain,
)


def _f(agent: str) -> SimpleNamespace:
    return SimpleNamespace(agent=agent, title=f"from {agent}")


def test_network_agents_map_to_network():
    for agent in ("recon", "intel", "exploit", "orchestrator", "planner"):
        assert domain_for(_f(agent)) == NETWORK


def test_mcp_and_web3_agents_map_to_own_domain():
    assert domain_for(_f("mcp_scan")) == MCP
    assert domain_for(_f("web3")) == WEB3


def test_unknown_agent_falls_back_to_network():
    assert domain_for(_f("brand_new_agent")) == NETWORK
    assert domain_for(_f("")) == NETWORK
    assert domain_for(SimpleNamespace()) == NETWORK


def test_agent_matching_is_case_and_space_insensitive():
    assert domain_for(_f("  MCP_Scan ")) == MCP
    assert domain_for(_f("WEB3")) == WEB3


def test_dict_findings_are_supported():
    assert domain_for({"agent": "mcp_scan"}) == MCP
    assert domain_for({"title": "no agent key"}) == NETWORK


def test_group_drops_empty_domains_and_keeps_order():
    grouped = group_by_domain([_f("web3"), _f("recon"), _f("mcp_scan"), _f("intel")])
    assert list(grouped) == [NETWORK, MCP, WEB3]
    assert [f.agent for f in grouped[NETWORK]] == ["recon", "intel"]
    assert len(grouped[MCP]) == 1 and len(grouped[WEB3]) == 1


def test_group_of_single_domain_yields_one_bucket():
    grouped = group_by_domain([_f("recon"), _f("exploit")])
    assert list(grouped) == [NETWORK]


def test_group_of_nothing_is_empty():
    assert group_by_domain([]) == {}
    assert DOMAIN_ORDER == (NETWORK, MCP, WEB3)
