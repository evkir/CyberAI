"""
Shared type aliases across all agent modules.
Centralises type hints — import from here, not redefine everywhere.
"""

from typing import Any, Union
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

# Target types
Target = str  # IP, CIDR, or domain
PortNumber = int  # 1-65535
ServiceName = str  # "http", "ssh", etc.

# Agent I/O
AgentInput = dict[str, Any]  # input to any agent
AgentOutput = dict[str, Any]  # output from any agent

# Recon
PortList = list[PortNumber]
ServiceMap = dict[str, ServiceName]  # "80" -> "http"


class OpenPort(BaseModel):
    """A single open port discovered during recon."""

    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str | None = None


class ReconResult(BaseModel):
    """Structured output of the ReconAgent."""

    target: str
    ports: list[OpenPort] = Field(default_factory=list)
    whois: dict[str, Any] = Field(default_factory=dict)
    dns: dict[str, Any] = Field(default_factory=dict)
    subdomains: list[str] = Field(default_factory=list)


# Intel
CVEId = str  # "CVE-2024-1234"
CVEList = list[CVEId]
RiskLevel = str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"


class CVEEntry(BaseModel):
    """A single CVE with scoring and threat-intel context."""

    id: str
    cvss: float = 0.0
    severity: str = "UNKNOWN"
    description: str = ""
    published: str | None = None
    exploited_in_wild: bool = False
    epss: float = 0.0


class IntelResult(BaseModel):
    """Structured output of the IntelAgent."""

    target: str
    cves: list[CVEEntry] = Field(default_factory=list)
    services: dict[str, Any] = Field(default_factory=dict)


# Exploit


class AttackPath(BaseModel):
    """A single attack path derived from one CVE."""

    cve_id: str
    attack_vector: str = "Unknown"
    attack_complexity: str = "Unknown"
    technique: str = ""
    success_probability: float = 0.0
    requires_auth: bool = False
    requires_interaction: bool = False
    notes: str = ""


class ExploitChain(BaseModel):
    """An ordered, MITRE-mapped sequence of exploitation steps."""

    target: str
    chain_length: int = 0
    steps: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


class ExploitResult(BaseModel):
    """Structured output of the ExploitAgent."""

    target: str
    attack_paths: list[AttackPath] = Field(default_factory=list)
    chain: ExploitChain | None = None
    ai_analysis: str = ""


# Report
ReportPath = Path
ReportFormat = str  # "markdown" | "html" | "json" | "pdf"

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class ReportSection(BaseModel):
    """LLM-generated structured report section (structured outputs).

    `impact` is included for HackerOne-style export; not in the original
    plan column but required by the H1 template.
    """

    title: str
    severity: str = "INFO"
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    impact: str = ""

    @field_validator("severity")
    @classmethod
    def _norm_severity(cls, v: str) -> str:
        up = (v or "INFO").strip().upper()
        return up if up in _VALID_SEVERITIES else "INFO"


# Pipeline
PipelineInput = Target
PipelineOutput = dict[str, AgentOutput]

# Safety
ScopeEntry = Union[str, None]  # IP, CIDR, or domain string
