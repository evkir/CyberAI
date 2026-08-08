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

# Parameter names that carry a user turn to an LLM or RAG backend. The name
# is the discriminator, not the path: measured over 751 recorded endpoints on
# two targets, the parameter matched only POST /rest/chat (7 runs, zero false
# positives), while a path-substring test flagged three basket routes because
# "ask" is a substring of "basket". Only "messages" has been observed in the
# wild here; the rest are the same field under other conventions.
_PROMPT_PARAMS = frozenset({"messages", "message", "prompt", "query", "question", "input", "text"})

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

    _add_llm_endpoints(g, kb, root)
    _add_http_endpoints(g, kb, root)
    _add_cves(g, kb, root)
    return g


def _add_llm_endpoints(g: nx.DiGraph, kb: KnowledgeBase, root: Node) -> None:
    """Add LLM/RAG endpoint nodes from both recon paths that find them.

    The dedicated detector probes a fixed candidate-path list with GET, so a
    POST-only chat API is invisible to it: on Juice Shop a GET of the real
    /rest/chat is indistinguishable from a GET of a path that does not exist,
    and the run reports is_llm_target=false while the web surface holds the
    endpoint the whole time. The surface also carries what the detector
    cannot know -- the method and the field name the channel reads -- so a
    consumer no longer has to guess the request body.

    Node identity stays the bare URL, matching the detector, so an endpoint
    found by both is one node carrying the surface's attributes.
    """
    llm = kb.get("recon.llm_endpoints") or {}
    if isinstance(llm, dict) and llm.get("is_llm_target"):
        for ep in llm.get("llm_endpoints") or []:
            url = ep.get("url") if isinstance(ep, dict) else None
            if not url:
                continue
            g.add_edge(root, _add_node(g, LLM_ENDPOINT, url), rel=EXPOSES)

    surface = kb.get("recon.web_surface") or {}
    if not isinstance(surface, dict):
        return
    for entry in list(surface.get("endpoints") or []) + list(surface.get("routes") or []):
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not url:
            continue
        params = list(entry.get("params") or []) + list(entry.get("body_params") or [])
        field = next((p for p in params if p in _PROMPT_PARAMS), None)
        if field is None:
            continue
        node = _add_node(
            g,
            LLM_ENDPOINT,
            url,
            prompt_field=field,
            method=str(entry.get("method") or "POST").upper(),
        )
        g.add_edge(root, node, rel=EXPOSES)


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
