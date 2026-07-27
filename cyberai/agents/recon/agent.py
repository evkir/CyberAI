"""ReconAgent — nmap → whois → DNS → subdomain enumeration."""

from __future__ import annotations

from typing import Any, Dict, Optional

from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.scan_session import Severity
from cyberai.core.types import OpenPort, ReconResult

from .dns_tool import detect_subdomains, run_dns, run_whois
from .llm_detector import detect_llm_endpoints
from .web_surface import discover_surface
from .behavioral import BehavioralFingerprint
from .behavioral_probe import build_probe_context
from .nmap_tool import run_nmap


class ReconAgent(BaseAgent):
    """
    Reconnaissance agent.
    Runs nmap → whois → DNS → subdomain enum, stores results in the KB.
    """

    AGENT_NAME = "recon"
    ROLE = "Reconnaissance Specialist"

    def _register_tools(self) -> None:
        self.register_tool(
            Tool(
                name="nmap_scan",
                description="Port scan target with nmap",
                func=run_nmap,
                parameters={"target": "str", "flags": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="whois_lookup",
                description="WHOIS lookup for domain info",
                func=run_whois,
                parameters={"target": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="dns_enum",
                description="DNS record enumeration",
                func=run_dns,
                parameters={"target": "str"},
            )
        )
        self.register_tool(
            Tool(
                name="subdomain_scan",
                description="Subdomain bruteforce",
                func=detect_subdomains,
                parameters={"target": "str"},
            )
        )

    def run(self, target: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {}

        # 1. nmap
        self._check_iteration_limit()
        nmap_flags = "-sV -T4 --top-ports 1000"
        max_rps = getattr(self.config, "max_rps", None)
        if max_rps:
            nmap_flags += f" --max-rate {max_rps}"
        nmap_result = run_nmap(target, flags=nmap_flags)
        self.kb.set("recon.nmap", nmap_result, agent=self.AGENT_NAME)
        results["recon.nmap"] = nmap_result
        if nmap_result.get("error"):
            self._log(f"nmap_scan FAILED: {nmap_result['error']}", nmap_result)
        else:
            self._log("nmap_scan complete", nmap_result)

        # 1b. Behavioral fingerprint (flag-gated) — honeypot/WAF/tarpit trust.
        if getattr(self.config, "use_behavioral_fingerprint", False):
            self._check_iteration_limit()
            ports_bf = nmap_result.get("ports", []) if isinstance(nmap_result, dict) else []
            mass_open = (
                bool(nmap_result.get("mass_open")) if isinstance(nmap_result, dict) else False
            )
            ctx = build_probe_context(target, ports_bf, mass_open=mass_open)
            if ctx.note:
                self._log(ctx.note, {"target": target})
            bf = BehavioralFingerprint()
            bf_result = bf.run(
                target,
                probe_fn=ctx.probe_fn,
                headers=ctx.headers,
                banners=ctx.banners,
            )
            bf.record(bf_result, self.session, agent=self.AGENT_NAME)
            results["recon.trust"] = bf_result.to_dict()
            self._log("behavioral_fingerprint complete", bf_result.to_dict())

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

        # 5. LLM/RAG endpoint discovery — flags an injection-fuzzing surface.
        self._check_iteration_limit()
        llm_result = detect_llm_endpoints(target)
        self.kb.set("recon.llm_endpoints", llm_result, agent=self.AGENT_NAME)
        results["recon.llm_endpoints"] = llm_result
        self._log("llm_endpoint_detect complete", llm_result)

        if llm_result.get("is_llm_target"):
            eps = llm_result.get("llm_endpoints", [])
            self.session.add_finding(
                severity=Severity.INFO,
                title=f"LLM/RAG endpoint(s) detected on {target}",
                description=(
                    f"Found {len(eps)} candidate LLM/RAG endpoint(s); "
                    "candidate surface for injection fuzzing."
                ),
                agent=self.AGENT_NAME,
                target=target,
                evidence=[e["url"] for e in eps],
            )

        # 6. HTTP attack surface — the injectable points exploitation needs.
        if getattr(self.config, "use_web_recon", False):
            self._check_iteration_limit()
            surface = discover_surface(target)
            self.kb.set("recon.web_surface", surface, agent=self.AGENT_NAME)
            results["recon.web_surface"] = surface
            self._log("web_surface complete", surface)

            eps = surface.get("endpoints", [])
            if eps:
                self.session.add_finding(
                    severity=Severity.INFO,
                    title=f"HTTP attack surface on {target}",
                    description=(
                        f"Discovered {len(eps)} endpoint(s) carrying injectable "
                        "parameters across the web target."
                    ),
                    agent=self.AGENT_NAME,
                    target=target,
                    evidence=[f"{e['method']} {e['url']} ({', '.join(e['params'])})" for e in eps],
                )

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
            subdomains=(sub_result.get("subdomains", []) if isinstance(sub_result, dict) else []),
        )
        self.kb.set("recon.result", recon_result.model_dump(), agent=self.AGENT_NAME)

        return {"status": "done", "kb_keys": list(results.keys()), "ports": ports}
