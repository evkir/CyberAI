"""ReconAgent — nmap → whois → DNS → subdomain enumeration."""
from __future__ import annotations

from typing import Any, Dict, Optional

from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.scan_session import Severity
from cyberai.core.types import OpenPort, ReconResult

from .dns_tool import detect_subdomains, run_dns, run_whois
from .nmap_tool import run_nmap


class ReconAgent(BaseAgent):
    """
    Reconnaissance agent.
    Runs nmap → whois → DNS → subdomain enum, stores results in the KB.
    """

    AGENT_NAME = "recon"
    ROLE = "Reconnaissance Specialist"

    def _register_tools(self) -> None:
        self.register_tool(Tool(
            name="nmap_scan",
            description="Port scan target with nmap",
            func=run_nmap,
            parameters={"target": "str", "flags": "str"},
        ))
        self.register_tool(Tool(
            name="whois_lookup",
            description="WHOIS lookup for domain info",
            func=run_whois,
            parameters={"target": "str"},
        ))
        self.register_tool(Tool(
            name="dns_enum",
            description="DNS record enumeration",
            func=run_dns,
            parameters={"target": "str"},
        ))
        self.register_tool(Tool(
            name="subdomain_scan",
            description="Subdomain bruteforce",
            func=detect_subdomains,
            parameters={"target": "str"},
        ))

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {}

        # 1. nmap
        self._check_iteration_limit()
        nmap_result = run_nmap(target)
        self.kb.set("recon.nmap", nmap_result, agent=self.AGENT_NAME)
        results["recon.nmap"] = nmap_result
        self._log("nmap_scan complete", nmap_result)

        # 2. whois
        self._check_iteration_limit()
        whois_result = run_whois(target)
        self.kb.set("recon.whois", whois_result, agent=self.AGENT_NAME)
        results["recon.whois"] = whois_result
        self._log("whois_lookup complete", whois_result)

        # 3. DNS
        self._check_iteration_limit()
        dns_result = run_dns(target)
        self.kb.set("recon.dns", dns_result, agent=self.AGENT_NAME)
        results["recon.dns"] = dns_result
        self._log("dns_enum complete", dns_result)

        # 4. Subdomains
        self._check_iteration_limit()
        sub_result = detect_subdomains(target)
        self.kb.set("recon.subdomains", sub_result, agent=self.AGENT_NAME)
        results["recon.subdomains"] = sub_result
        self._log("subdomain_scan complete", sub_result)

        # Surface open ports as an informational finding
        ports = nmap_result.get("ports", []) if isinstance(nmap_result, dict) else []
        if ports:
            self.session.add_finding(
                severity=Severity.INFO,
                title=f"Open ports on {target}",
                description=f"Found {len(ports)} open port(s)",
                agent=self.AGENT_NAME,
                target=target,
                evidence=[str(p) for p in ports],
            )

        # Build a validated pydantic ReconResult and store it in the KB.
        recon_result = ReconResult(
            target=target,
            ports=[OpenPort(**p) for p in ports if isinstance(p, dict)],
            whois=whois_result if isinstance(whois_result, dict) else {},
            dns=dns_result if isinstance(dns_result, dict) else {},
            subdomains=(
                sub_result.get("subdomains", [])
                if isinstance(sub_result, dict) else []
            ),
        )
        self.kb.set("recon.result", recon_result.model_dump(), agent=self.AGENT_NAME)

        return {"status": "done", "kb_keys": list(results.keys()), "ports": ports}
