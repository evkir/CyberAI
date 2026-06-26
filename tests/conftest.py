"""
Shared pytest fixtures for CyberAI test suite.

Note: The `fresh_session` fixture currently uses PentestSession.
This will change to ScanSession in a later refactor,
when the two competing session types are unified.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from cyberai.core.config import CyberAIConfig
from cyberai.core.session import PentestSession


# ---------------------------------------------------------------------------
# Config & sessions
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def base_config() -> CyberAIConfig:
    """Shared config for all tests — no real API keys needed."""
    return CyberAIConfig()


@pytest.fixture
def fresh_session() -> PentestSession:
    """A clean session for each test that needs one."""
    return PentestSession(target="testhost.local")


@pytest.fixture
def session_with_recon(fresh_session: PentestSession) -> PentestSession:
    """Session pre-loaded with synthetic recon data."""
    fresh_session.recon_data["nmap"] = {
        "ports": [
            {"port": 80, "service": "http", "state": "open"},
            {"port": 22, "service": "ssh", "state": "open"},
        ]
    }
    return fresh_session


# ---------------------------------------------------------------------------
# Mocked external services
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm_client() -> MagicMock:
    """
    A MagicMock that mimics the LLMClient interface.

    Returns a deterministic response for `call()` and `acall()`,
    so tests don't need real API keys and don't hit the network.

    Usage:
        def test_something(mock_llm_client):
            mock_llm_client.call.return_value = "custom response"
            agent = SomeAgent(llm=mock_llm_client, ...)
            ...
    """
    client = MagicMock()
    client.call.return_value = "stub LLM response"
    client.acall.return_value = "stub async LLM response"
    client.model = "stub-model"
    client.provider = "stub-provider"
    return client


@pytest.fixture
def mock_nmap_result() -> dict[str, Any]:
    """
    Realistic-ish nmap output structure for tests that need recon data
    without actually running nmap.
    """
    return {
        "target": "testhost.local",
        "ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.9p1 Ubuntu",
            },
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "version": "Apache 2.4.52",
            },
            {
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "service": "https",
                "version": "Apache 2.4.52",
            },
        ],
        "scan_time": "12.3s",
    }


@pytest.fixture
def mock_nvd_response() -> dict[str, Any]:
    """Minimal NVD API 2.0 response shape for one CVE."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "published": "2024-01-15T00:00:00.000",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    ),
                                }
                            }
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "Synthetic test CVE for fixtures."}],
                }
            }
        ],
    }
