"""HTTP endpoint nodes in the KB graph."""

from __future__ import annotations

from cyberai.core.kb_graph import (
    HOST,
    HTTP_ENDPOINT,
    LLM_ENDPOINT,
    SERVES,
    build_kb_graph,
    nodes_by_type,
)
from cyberai.core.scan_session import ScanSession

TARGET = "acme.tld"
BASE = "http://acme.tld"


def _session(surface=None) -> ScanSession:
    s = ScanSession(target=TARGET)
    s.kb.set("recon.result", {"target": TARGET})
    if surface is not None:
        s.kb.set("recon.web_surface", surface)
    return s


def _attrs(g, name):
    return g.nodes[(HTTP_ENDPOINT, name)]


def test_endpoints_and_routes_become_nodes():
    g = build_kb_graph(
        _session(
            {
                "endpoints": [
                    {
                        "url": f"{BASE}/switch_personal_path",
                        "method": "GET",
                        "params": ["path"],
                        "body_params": ["path"],
                        "source": "openapi",
                    }
                ],
                "routes": [{"url": f"{BASE}/done", "method": "GET", "params": []}],
            }
        ).kb
    )
    names = sorted(n[1] for n in nodes_by_type(g, HTTP_ENDPOINT))
    assert names == [f"GET {BASE}/done", f"GET {BASE}/switch_personal_path"]

    ep = _attrs(g, f"GET {BASE}/switch_personal_path")
    assert ep["url"] == f"{BASE}/switch_personal_path"
    assert ep["method"] == "GET"
    assert ep["params"] == ["path"]
    assert ep["body_params"] == ["path"]
    assert ep["source"] == "openapi"

    # A parameterless route is still surface, distinguishable by empty params.
    assert _attrs(g, f"GET {BASE}/done")["params"] == []


def test_endpoints_hang_off_the_root_host():
    g = build_kb_graph(_session({"endpoints": [{"url": f"{BASE}/x", "params": ["q"]}]}).kb)
    edge = g.edges[(HOST, TARGET), (HTTP_ENDPOINT, f"GET {BASE}/x")]
    assert edge["rel"] == SERVES


def test_method_is_part_of_identity():
    g = build_kb_graph(
        _session(
            {
                "endpoints": [
                    {"url": f"{BASE}/item", "method": "GET", "params": ["id"]},
                    {"url": f"{BASE}/item", "method": "POST", "params": ["name"]},
                ]
            }
        ).kb
    )
    assert len(nodes_by_type(g, HTTP_ENDPOINT)) == 2
    assert _attrs(g, f"POST {BASE}/item")["params"] == ["name"]


def test_method_defaults_to_get_and_is_upper_cased():
    g = build_kb_graph(
        _session({"endpoints": [{"url": f"{BASE}/a", "method": "post", "params": ["q"]}]}).kb
    )
    assert _attrs(g, f"POST {BASE}/a")["method"] == "POST"

    g = build_kb_graph(_session({"endpoints": [{"url": f"{BASE}/b", "params": ["q"]}]}).kb)
    assert _attrs(g, f"GET {BASE}/b")["method"] == "GET"


def test_missing_or_malformed_surface_adds_nothing():
    assert nodes_by_type(build_kb_graph(_session().kb), HTTP_ENDPOINT) == []
    assert nodes_by_type(build_kb_graph(_session("not-a-dict").kb), HTTP_ENDPOINT) == []
    surface = {"endpoints": [None, {"method": "GET"}, {"url": ""}], "routes": ["nope"]}
    assert nodes_by_type(build_kb_graph(_session(surface).kb), HTTP_ENDPOINT) == []


# ── LLM endpoints discovered by the web surface ───────────────────────


def _llm_attrs(g, url):
    return g.nodes[(LLM_ENDPOINT, url)]


def test_llm_endpoint_from_surface_carries_its_contract():
    """A chat route the GET detector cannot see still reaches the graph."""
    g = build_kb_graph(
        _session(
            {
                "endpoints": [
                    {
                        "url": f"{BASE}/rest/chat",
                        "method": "POST",
                        "params": ["messages"],
                        "source": "js-route",
                    },
                    {
                        "url": f"{BASE}/rest/products/search",
                        "method": "GET",
                        "params": ["q"],
                        "source": "js-route",
                    },
                ]
            }
        ).kb
    )

    assert [n[1] for n in nodes_by_type(g, LLM_ENDPOINT)] == [f"{BASE}/rest/chat"]
    attrs = _llm_attrs(g, f"{BASE}/rest/chat")
    assert attrs["prompt_field"] == "messages"
    assert attrs["method"] == "POST"


def test_a_prompt_field_in_the_body_counts():
    """The field can be declared as a body parameter rather than a query one."""
    g = build_kb_graph(
        _session(
            {"endpoints": [{"url": f"{BASE}/ask", "method": "POST", "body_params": ["prompt"]}]}
        ).kb
    )

    assert _llm_attrs(g, f"{BASE}/ask")["prompt_field"] == "prompt"


def test_a_path_that_merely_looks_like_a_chat_route_is_not_one():
    """Control: 'ask' is a substring of 'basket' — the parameter decides."""
    g = build_kb_graph(
        _session(
            {
                "endpoints": [
                    {
                        "url": f"{BASE}/rest/basket/x/checkout",
                        "method": "POST",
                        "params": ["couponData", "e", "orderDetails"],
                    }
                ]
            }
        ).kb
    )

    assert nodes_by_type(g, LLM_ENDPOINT) == []


def test_the_detector_path_still_produces_nodes():
    """Control: the original producer keeps working alongside the new one."""
    session = _session()
    session.kb.set(
        "recon.llm_endpoints",
        {"is_llm_target": True, "llm_endpoints": [{"url": f"{BASE}/v1/chat/completions"}]},
    )

    g = build_kb_graph(session.kb)

    assert [n[1] for n in nodes_by_type(g, LLM_ENDPOINT)] == [f"{BASE}/v1/chat/completions"]
