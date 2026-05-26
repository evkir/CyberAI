"""IntelAgent — reads recon results, queries NVD, surfaces CVE findings."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.scan_session import Severity

from .nvd_client import get_cve, search_cves
from .service_mapper import ports_to_queries, score_to_severity
from cyberai.core.types import CVEEntry, IntelResult


class IntelAgent(BaseAgent):
    """
    CVE Intelligence Agent.
    Reads recon results → queries NVD → surfaces critical findings.

    Set score_cves=True to also run the risk-prioritizer and produce
    a ranked CVE list (this replaces the old IntelAgentV2 subclass).
    """

    AGENT_NAME = "intel"
    ROLE = "Threat Intelligence Analyst"

    def __init__(self, *args, score_cves: bool = True,
                 min_score: float = 0.0, top_n: int = 10, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.score_cves = score_cves
        self.min_score = min_score
        self.top_n = top_n

    def _register_tools(self) -> None:
        self.register_tool(Tool(
            name="search_cves",
            description="Search NVD for CVEs by keyword",
            func=search_cves,
            parameters={"keyword": "str", "max_results": "int"},
        ))
        self.register_tool(Tool(
            name="get_cve",
            description="Get details for a specific CVE ID",
            func=get_cve,
            parameters={"cve_id": "str"},
        ))

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        nmap_data = self.kb.get("recon.nmap", {}) or {}
        ports = nmap_data.get("ports", []) if isinstance(nmap_data, dict) else []

        if not ports:
            self._log("no ports found in KB — skipping CVE lookup")
            return {"status": "skipped", "reason": "no ports"}

        queries = ports_to_queries(ports)
        all_cves: List[Dict] = []

        for query in queries[:5]:  # NVD rate limit
            self._check_iteration_limit()
            result = search_cves(query, max_results=5)
            all_cves.extend(result.get("cves", []))
            time.sleep(0.6)

        self.kb.set("intel.cves", all_cves, agent=self.AGENT_NAME)
        self._log(f"found {len(all_cves)} CVEs for {len(queries)} services")

        # Surface high/critical CVEs as findings
        for cve in all_cves:
            score = (cve.get("cvss", {}) or {}).get("score") or 0
            if score >= 7.0:
                sev = getattr(Severity, score_to_severity(score), Severity.HIGH)
                self.session.add_finding(
                    severity=sev,
                    title=cve["id"],
                    description=cve.get("description", ""),
                    agent=self.AGENT_NAME,
                    target=target,
                    cve_ids=[cve["id"]],
                    evidence=[f"CVSS: {score}",
                              (cve.get("cvss", {}) or {}).get("vector", "")],
                )

        # Build a validated IntelResult and store it in the KB.
        def _cvss_score(c: dict) -> float:
            raw = c.get("cvss")
            if isinstance(raw, dict):
                return float(raw.get("score") or 0.0)
            return float(raw or 0.0)

        intel_result = IntelResult(
            target=target,
            cves=[
                CVEEntry(
                    id=c.get("id") or c.get("cve_id", ""),
                    cvss=_cvss_score(c),
                    severity=score_to_severity(_cvss_score(c)),
                    description=c.get("description", ""),
                    published=c.get("published") or None,
                    exploited_in_wild=c.get("exploited_in_wild", False),
                    epss=float(c.get("epss") or 0.0),
                )
                for c in all_cves
            ],
        )
        self.kb.set("intel.result", intel_result.model_dump(), agent=self.AGENT_NAME)

        result = {
            "status": "done",
            "queries": queries,
            "cves_found": len(all_cves),
            "high_critical": sum(
                1 for c in all_cves
                if ((c.get("cvss", {}) or {}).get("score") or 0) >= 7.0
            ),
        }

        if self.score_cves:
            result.update(self._score(all_cves))

        return result

    def _score(self, raw_cves: List[Dict]) -> Dict[str, Any]:
        """Run the risk-prioritizer (formerly IntelAgentV2)."""
        if not raw_cves:
            return {"ranked_cves": [], "risk_summary": {}}

        normalized = [_normalize(c) for c in raw_cves]

        from cyberai.agents.intel.risk_prioritizer import prioritize, summarize
        ranked = prioritize(normalized, min_score=self.min_score, top_n=self.top_n)
        summary = summarize(normalized)

        self.kb.set("intel.ranked_cves", ranked, agent=self.AGENT_NAME)
        self.kb.set("intel.risk_summary", summary, agent=self.AGENT_NAME)

        if ranked:
            self._log(
                f"scored {len(ranked)} CVEs | top={ranked[0]['cve_id']} "
                f"({ranked[0].get('composite_score', 0):.2f})"
            )
        else:
            self._log("no CVEs after scoring")

        return {"ranked_cves": ranked, "risk_summary": summary}


# Backward-compat alias — IntelAgentV2 was a subclass; now scoring is built in.
IntelAgentV2 = IntelAgent


def _normalize(cve: dict) -> dict:
    """Normalize NVD CVE dict to scorer-expected format."""
    cvss_raw = cve.get("cvss") or 0
    cvss_block = cvss_raw if isinstance(cvss_raw, dict) else {}
    score = cvss_block.get("score") if cvss_block else cvss_raw
    return {
        "cve_id": cve.get("id") or cve.get("cve_id", ""),
        "cvss": float(score) if score else 0.0,
        "description_short": cve.get("description", "")[:120],
        "published_date": cve.get("published", ""),
        "poc_likely": cve.get("poc_likely", False),
        "metasploit": cve.get("metasploit", False),
        "exploited_in_wild": cve.get("exploited_in_wild", False),
        "epss": float(cve.get("epss") or 0.0),
    }
