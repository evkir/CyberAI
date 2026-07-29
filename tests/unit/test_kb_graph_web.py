"""HTTP endpoint nodes in the KB graph."""

from __future__ import annotations

from cyberai.core.kb_graph import (
    HOST,
    HTTP_ENDPOINT,
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
