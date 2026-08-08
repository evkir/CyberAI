"""Planner agent.

Turns the knowledge-base relationship graph into an ordered list of concrete
subtasks (a TODO plan) that later phases can act on. Deterministic by default:
CVE nodes become exploitation subtasks ranked by score, HTTP endpoints with
injectable parameters become web-exploitation subtasks, LLM/RAG endpoints
become injection-fuzzing subtasks, and remaining services become enumeration
subtasks. Which endpoints matter is decided here; the order payloads are tried
in stays with the exploitation layer, so there is one source of truth for each. The plan and a serialised graph are written to the KB under ``plan``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from cyberai.core.base_agent import BaseAgent
from cyberai.core.kb_graph import (
    CVE,
    HOST,
    HTTP_ENDPOINT,
    LLM_ENDPOINT,
    SERVICE,
    attack_paths,
    build_kb_graph,
    nodes_by_type,
    to_dict,
)


def _score(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class PlannerAgent(BaseAgent):
    """Derive an ordered subtask plan from the KB graph."""

    AGENT_NAME = "planner"
    ROLE = "Attack Planner"

    def _register_tools(self) -> None:  # no external tools — pure reasoning
        pass

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._check_iteration_limit()
        graph = build_kb_graph(self.kb, target)
        todo = self._plan_from_graph(graph, target)

        plan = {"target": target, "todo": todo, "graph": to_dict(graph)}
        self.session.kb_set("plan", plan)
        self.log(f"planned {len(todo)} subtask(s)", {"count": len(todo)})
        return {"status": "done", "subtasks": len(todo), "todo": todo}

    def _plan_from_graph(self, graph: Any, target: str) -> List[Dict[str, Any]]:
        root = (HOST, target)
        subtasks: List[Dict[str, Any]] = []

        cve_nodes = nodes_by_type(graph, CVE)
        cve_nodes.sort(key=lambda n: _score(graph.nodes[n].get("score")), reverse=True)
        for node in cve_nodes:
            paths = attack_paths(graph, root, node)
            subtasks.append(
                {
                    "action": "exploit",
                    "target": node[1],
                    "severity": graph.nodes[node].get("severity"),
                    "score": graph.nodes[node].get("score"),
                    "path": [n[1] for n in paths[0]] if paths else [target, node[1]],
                }
            )

        for node in nodes_by_type(graph, HTTP_ENDPOINT):
            attrs = graph.nodes[node]
            params = attrs.get("params") or []
            if not params:
                # A route with no parameters offers nothing to inject; it stays
                # in the graph as reachable surface but earns no subtask.
                continue
            subtasks.append(
                {
                    "action": "web-exploit",
                    "target": attrs.get("url"),
                    "method": attrs.get("method"),
                    "params": list(params),
                    "body_params": list(attrs.get("body_params") or []),
                    "path": [target, attrs.get("url")],
                }
            )

        for node in nodes_by_type(graph, LLM_ENDPOINT):
            attrs = graph.nodes[node]
            subtasks.append(
                {
                    "action": "injection-fuzz",
                    "target": node[1],
                    "method": attrs.get("method"),
                    "prompt_field": attrs.get("prompt_field"),
                    "path": [target, node[1]],
                }
            )

        for node in nodes_by_type(graph, SERVICE):
            subtasks.append({"action": "enumerate", "target": node[1]})

        for idx, task in enumerate(subtasks, start=1):
            task["id"] = idx
        return subtasks
