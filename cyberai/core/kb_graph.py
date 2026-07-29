"""In-memory knowledge-base graph.

Builds a directed relationship graph from KnowledgeBase entries so a planner
can reason over multi-step attack paths (host -> port -> service -> CVE,
and host -> HTTP endpoint for web surface).
Backed by networkx and held entirely in memory — no external graph database —
to keep the pipeline air-gapped.

Node identity is a ``(node_type, name)`` tuple; every node also carries an
``ntype`` attribute for filtering. Edges carry a ``rel`` label describing the
relationship between endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from cyberai.core.knowledge_base import KnowledgeBase

Node = Tuple[str, str]

# Node types.
HOST = "host"
PORT = "port"
SERVICE = "service"
CVE = "cve"
LLM_ENDPOINT = "llm_endpoint"
HTTP_ENDPOINT = "http_endpoint"

# Edge relations.
HAS_PORT = "HAS_PORT"
RUNS = "RUNS"
VULN_TO = "VULN_TO"
SUBDOMAIN = "SUBDOMAIN"
EXPOSES = "EXPOSES"
SERVES = "SERVES"


def _add_node(g: nx.DiGraph, ntype: str, name: Any, **attrs: Any) -> Node:
    node: Node = (ntype, str(name))
    g.add_node(node, ntype=ntype, name=str(name), **attrs)
    return node


def build_kb_graph(kb: KnowledgeBase, target: Optional[str] = None) -> nx.DiGraph:
    """Assemble a relationship graph from recon/intel entries in ``kb``.

    ``target`` anchors the root host node; when omitted it is taken from the
    stored recon result. Returns an empty graph if no anchor can be found.
    """
    g: nx.DiGraph = nx.DiGraph()

    recon = kb.get("recon.result") or {}
    if not isinstance(recon, dict):
        recon = {}
    target = target or recon.get("target")
    if not target:
        return g

    root = _add_node(g, HOST, target)

    for p in recon.get("ports") or []:
        if not isinstance(p, dict):
            continue
        num = p.get("port")
        if num is None:
            continue
        pnode = _add_node(
            g,
            PORT,
            f"{target}:{num}",
            port=num,
            protocol=p.get("protocol", "tcp"),
            version=p.get("version"),
        )
        g.add_edge(root, pnode, rel=HAS_PORT)

        svc = p.get("service") or "unknown"
        if svc != "unknown":
            snode = _add_node(g, SERVICE, svc)
            g.add_edge(pnode, snode, rel=RUNS)

    for sub in recon.get("subdomains") or []:
        if not sub:
            continue
        g.add_edge(root, _add_node(g, HOST, sub), rel=SUBDOMAIN)

    llm = kb.get("recon.llm_endpoints") or {}
    if isinstance(llm, dict) and llm.get("is_llm_target"):
        for ep in llm.get("llm_endpoints") or []:
            url = ep.get("url") if isinstance(ep, dict) else None
            if not url:
                continue
            g.add_edge(root, _add_node(g, LLM_ENDPOINT, url), rel=EXPOSES)

    _add_http_endpoints(g, kb, root)
    _add_cves(g, kb, root)
    return g


def _add_http_endpoints(g: nx.DiGraph, kb: KnowledgeBase, root: Node) -> None:
    """Add HTTP endpoint nodes from the web surface recon discovered.

    Identity is method plus URL, because the surface keys endpoints by that
    pair: one path can expose different parameters per method, and collapsing
    them would lose a route. Parameterless routes are recorded as well -- they
    describe reachable surface even though nothing can be injected into them
    yet, and a consumer can tell them apart by an empty ``params``.
    """
    surface = kb.get("recon.web_surface") or {}
    if not isinstance(surface, dict):
        return
    entries = list(surface.get("endpoints") or []) + list(surface.get("routes") or [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not url:
            continue
        method = str(entry.get("method") or "GET").upper()
        node = _add_node(
            g,
            HTTP_ENDPOINT,
            f"{method} {url}",
            url=str(url),
            method=method,
            params=list(entry.get("params") or []),
            body_params=list(entry.get("body_params") or []),
            source=entry.get("source"),
        )
        g.add_edge(root, node, rel=SERVES)


def _add_cves(g: nx.DiGraph, kb: KnowledgeBase, root: Node) -> None:
    service_nodes = {d["name"]: n for n, d in g.nodes(data=True) if d.get("ntype") == SERVICE}

    ranked = kb.get("intel.ranked_cves")
    if isinstance(ranked, list) and ranked:
        for c in ranked:
            if not isinstance(c, dict):
                continue
            cid = c.get("cve_id") or c.get("id")
            if not cid:
                continue
            cnode = _add_node(
                g,
                CVE,
                cid,
                score=c.get("composite_score", c.get("cvss")),
                severity=c.get("severity"),
            )
            _link_cve(g, cnode, c, service_nodes, root)
        return

    intel = kb.get("intel.result") or {}
    cves = intel.get("cves") if isinstance(intel, dict) else []
    for c in cves or []:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not cid:
            continue
        cnode = _add_node(g, CVE, cid, score=c.get("cvss"), severity=c.get("severity"))
        _link_cve(g, cnode, c, service_nodes, root)


def _link_cve(
    g: nx.DiGraph, cnode: Node, c: Dict[str, Any], service_nodes: Dict[str, Node], root: Node
) -> None:
    svc = c.get("service")
    if svc and svc in service_nodes:
        g.add_edge(service_nodes[svc], cnode, rel=VULN_TO)
    else:
        g.add_edge(root, cnode, rel=VULN_TO)


def nodes_by_type(g: nx.DiGraph, ntype: str) -> List[Node]:
    """All nodes of a given ``ntype``."""
    return [n for n, d in g.nodes(data=True) if d.get("ntype") == ntype]


def attack_paths(g: nx.DiGraph, source: Node, target: Node, cutoff: int = 6) -> List[List[Node]]:
    """Simple directed paths from ``source`` to ``target`` up to ``cutoff`` hops."""
    if source not in g or target not in g:
        return []
    return [list(p) for p in nx.all_simple_paths(g, source, target, cutoff=cutoff)]


def to_dict(g: nx.DiGraph) -> Dict[str, Any]:
    """Serialise the graph to a plain dict for storage or reporting."""
    return {
        "nodes": [{"type": d.get("ntype"), "name": d.get("name")} for _, d in g.nodes(data=True)],
        "edges": [
            {"from": u[1], "to": v[1], "rel": d.get("rel")} for u, v, d in g.edges(data=True)
        ],
    }
