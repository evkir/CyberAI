"""
Shared type aliases across all agent modules.
Centralises type hints — import from here, not redefine everywhere.
"""
from typing import Any, Union
from pathlib import Path

from pydantic import BaseModel, Field

# Target types
Target = str                        # IP, CIDR, or domain
PortNumber = int                    # 1-65535
ServiceName = str                   # "http", "ssh", etc.

# Agent I/O
AgentInput  = dict[str, Any]        # input to any agent
AgentOutput = dict[str, Any]        # output from any agent

# Recon
PortList     = list[PortNumber]
ServiceMap   = dict[str, ServiceName]   # "80" -> "http"


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
CVEId        = str                  # "CVE-2024-1234"
CVEList      = list[CVEId]
RiskLevel    = str                  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
IntelResult  = dict[str, Any]

# Exploit
AttackPath   = dict[str, Any]
ExploitResult = dict[str, Any]

# Report
ReportPath   = Path
ReportFormat = str                  # "markdown" | "html" | "json" | "pdf"

# Pipeline
PipelineInput  = Target
PipelineOutput = dict[str, AgentOutput]

# Safety
ScopeEntry = Union[str, None]       # IP, CIDR, or domain string
