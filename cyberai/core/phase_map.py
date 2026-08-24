"""The phase map: which agent and which tools each pipeline phase uses.

This table is a declaration of what the pipeline is made of, not a CLI
feature. It outlived the --dry-run printer that once rendered it: that
printer sat on a path no caller reached, while the table itself kept being
repaired because it kept going stale -- the exploit row once named two
modules deleted months earlier.

Nothing in the product reads this map today. It is kept, and pinned by
tests/unit/test_phase_map.py, because a stale description of the pipeline is
worse than no description: the pin fails the moment a named module stops
existing or a default phase loses its row.
"""

from __future__ import annotations

PHASE_TOOLS: dict[str, tuple[str, tuple[str, ...]]] = {
    "recon": (
        "ReconAgent",
        (
            "cyberai.agents.recon.nmap_tool",
            "cyberai.agents.recon.dns_tool",
            "cyberai.agents.recon.subdomain_enum",
            "cyberai.agents.recon.web_surface",
            "cyberai.agents.recon.llm_detector",
            "cyberai.agents.recon.behavioral",
            "cyberai.agents.recon.fingerprinter",
        ),
    ),
    "intel": (
        "IntelAgent",
        (
            "cyberai.agents.intel.nvd_client",
            "cyberai.agents.intel.epss_client",
            "cyberai.agents.intel.service_mapper",
            "cyberai.agents.intel.version_match",
            "cyberai.agents.intel.risk_prioritizer",
        ),
    ),
    "plan": (
        "PlannerAgent",
        (
            "cyberai.agents.planner.agent",
            "cyberai.agents.planner.critic",
        ),
    ),
    "exploit": (
        "ExploitAgent",
        (
            "cyberai.agents.exploit.chain_builder",
            "cyberai.agents.exploit.attack_path",
            "cyberai.agents.exploit.cvss_analyzer",
            "cyberai.agents.exploit.poc_mapper",
            "cyberai.agents.exploit.nuclei_engine",
            "cyberai.agents.exploit.web_exploit",
        ),
    ),
    "report": (
        "ReportAgent",
        (
            "cyberai.agents.report.markdown_renderer",
            "cyberai.agents.report.html_renderer",
            "cyberai.agents.report.json_exporter",
            "cyberai.agents.report.judge",
        ),
    ),
}
