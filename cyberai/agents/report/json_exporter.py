import json
from typing import Any, Dict
from pathlib import Path
from datetime import datetime, timezone
from cyberai.core.scan_session import ScanSession as PentestSession
from cyberai.version import __version__

from .domains import domain_for, group_by_domain


def export_json(session: PentestSession, output_dir: str = "reports/") -> str:
    """Export full session as structured JSON report"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = f"report_{session.target}_{timestamp}.json".replace(":", "_").replace("/", "_")
    filename = str(Path(output_dir) / stem)

    report = {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "tool": "CyberAI",
            "version": __version__,
        },
        "session": {
            "id": session.session_id,
            "target": session.target,
            "state": session.state.value,
            "created_at": session.created_at,
        },
        "summary": session.summary(),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "target": f.target,
                "cve_ids": f.cve_ids,
                "evidence": f.evidence,
                "agent": f.agent,
                "domain": domain_for(f),
                "timestamp": f.timestamp,
            }
            for f in session.findings
        ],
        "findings_by_domain": {
            domain: [f.id for f in items]
            for domain, items in group_by_domain(session.findings).items()
        },
        "attack_paths": (session.kb.get("exploit.attack_paths") or {}).get("attack_paths", []),
        # The Markdown document names 26 addresses on a Juice Shop run and this
        # file named none of them: attack_paths is a CVE-shaped key that a web
        # target never writes, and nothing read exploit.web at all. A machine
        # consumer of this report could not tell a walked surface from an
        # absent one.
        "web_exploitation": session.kb.get("exploit.web") or {},
        # Present even when empty, unlike the Markdown section which is
        # omitted when no model was asked. A key that comes and goes is a
        # break for whoever parses this; "" is an answer, a KeyError is not.
        "ai_analysis": (session.kb.get("exploit") or {}).get("ai_analysis", ""),
        # The channel fuzzer writes its counters and per-channel reports under
        # exploit.redteam, and no exporter read them: a run that fuzzed a live
        # LLM channel was indistinguishable, to a machine consumer, from a run
        # that never found one. Present even when empty, for the same reason as
        # ai_analysis above -- "" or {} is an answer, a KeyError is not.
        "redteam": (session.kb.get("exploit") or {}).get("redteam", {}),
        "knowledge_base_keys": list(session.kb.keys()),
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return filename


def export_summary(session: PentestSession) -> Dict[str, Any]:
    """Return lightweight summary dict — for CLI display"""
    return {
        **session.summary(),
        "findings_by_severity": {
            sev: [
                {"id": f.id, "title": f.title} for f in session.findings if f.severity.value == sev
            ]
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
        "findings_by_domain": {
            domain: [{"id": f.id, "title": f.title} for f in items]
            for domain, items in group_by_domain(session.findings).items()
        },
    }
