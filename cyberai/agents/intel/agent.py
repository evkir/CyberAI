from typing import Dict, Any, List
from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.session import Finding, Severity
from .nvd_client import search_cves, get_cve
from .service_mapper import ports_to_queries, score_to_severity
import time

class IntelAgent(BaseAgent):
    """
    CVE Intelligence Agent.
    Reads recon results → queries NVD → surfaces critical findings.
    """

    def _register_tools(self):
        self.register_tool(Tool(
            name="search_cves",
            description="Search NVD for CVEs by keyword",
            func=search_cves,
            parameters={"keyword": "str", "max_results": "int"}
        ))
        self.register_tool(Tool(
            name="get_cve",
            description="Get details for a specific CVE ID",
            func=get_cve,
            parameters={"cve_id": "str"}
        ))

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = self.session.target

        # Pull nmap results from session KB
        nmap_data = self.session.knowledge_base.get("recon.nmap", {})
        ports = nmap_data.get("ports", [])

        if not ports:
            self.log("intel", "no ports found in KB — skipping CVE lookup")
            return {"status": "skipped", "reason": "no ports"}

        # Build search queries from open ports
        queries = ports_to_queries(ports)
        all_cves: List[Dict] = []

        for query in queries[:5]:  # Limit to 5 queries — NVD rate limit
            self._check_iteration_limit()
            result = search_cves(query, max_results=5)
            cves = result.get("cves", [])
            all_cves.extend(cves)
            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key

        # Store in KB
        self.session.knowledge_base["intel.cves"] = all_cves
        self.log("intel", f"found {len(all_cves)} CVEs for {len(queries)} services")

        # Surface high/critical as findings
        for cve in all_cves:
            score = cve.get("cvss", {}).get("score") or 0
            if score >= 7.0:
                sev_str = score_to_severity(score)
                sev = getattr(Severity, sev_str, Severity.HIGH)
                self.session.add_finding(Finding(
                    title=cve["id"],
                    description=cve["description"],
                    severity=sev,
                    target=target,
                    cve_ids=[cve["id"]],
                    evidence=[f"CVSS: {score}", cve.get("cvss", {}).get("vector", "")],
                ))

        return {
            "status": "done",
            "queries": queries,
            "cves_found": len(all_cves),
            "high_critical": sum(
                1 for c in all_cves
                if (c.get("cvss", {}).get("score") or 0) >= 7.0
            )
        }


class IntelAgentV2(IntelAgent):
    """
    IntelAgent with CVE scoring engine wired in.
    Enriches CVEs with composite risk scores and ranked output.
    """

    def __init__(self, *args, min_score: float = 0.0,
                 top_n: int = 10, **kwargs):
        super().__init__(*args, **kwargs)
        self.min_score = min_score
        self.top_n     = top_n

    def run(self, input_data: dict) -> dict:
        result = super().run(input_data)

        if result.get("status") == "skipped":
            return result

        raw_cves = self.session.knowledge_base.get("intel.cves", [])
        if not raw_cves:
            return {**result, "ranked_cves": [], "risk_summary": {}}

        # Normalize CVE format for scorer
        normalized = [_normalize(c) for c in raw_cves]

        from cyberai.agents.intel.risk_prioritizer import prioritize, summarize
        ranked = prioritize(
            normalized,
            min_score=self.min_score,
            top_n=self.top_n,
        )
        summary = summarize(normalized)

        self.session.knowledge_base["intel.ranked_cves"] = ranked
        self.session.knowledge_base["intel.risk_summary"] = summary

        self.log("intel", (
            f"scored {len(ranked)} CVEs | "
            f"top={ranked[0]['cve_id'] if ranked else 'none'} "
            f"({ranked[0].get('composite_score', 0):.2f})"
            if ranked else "no CVEs after scoring"
        ))

        return {
            **result,
            "ranked_cves":  ranked,
            "risk_summary": summary,
        }


def _normalize(cve: dict) -> dict:
    """Normalize NVD CVE dict to scorer-expected format."""
    cvss_raw   = cve.get("cvss") or 0
    cvss_block = cvss_raw if isinstance(cvss_raw, dict) else {}
    score      = cvss_block.get("score") if cvss_block else cvss_raw
    return {
        "cve_id":         cve.get("id") or cve.get("cve_id", ""),
        "cvss":           float(score) if score else 0.0,
        "description_short": cve.get("description", "")[:120],
        "published_date": cve.get("published", ""),
        "poc_likely":     cve.get("poc_likely", False),
        "metasploit":     cve.get("metasploit", False),
        "exploited_in_wild": cve.get("exploited_in_wild", False),
        "epss":           float(cve.get("epss") or 0.0),
    }
