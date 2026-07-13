"""CLI surface of `cyberai web3 audit`: plain output and --immunefi export.

The Web3 agent is mocked so the command is exercised without Slither/Foundry or
network; only the CLI wiring and Immunefi rendering are under test.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cyberai.__main__ import cli


def _result() -> dict:
    return {
        "mode": "local",
        "highest_severity": "Critical",
        "findings": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "High",
                "description": "ETH before state",
                "contract": "Vault",
                "function": "withdraw",
                "immunefi_severity": "Critical",
            }
        ],
        "poc_findings": [
            {
                "check": "onchain-poc-exploit",
                "confirmed": True,
                "test": "testExploit()",
                "profit_wei": 1500 * 10**18,
                "contract": "Vault",
            }
        ],
    }


def _run(args: list[str], result: dict | None = None):
    fake = MagicMock()
    fake.run.return_value = _result() if result is None else result
    with (
        patch("cyberai.cli.web3_audit.CyberAIConfig"),
        patch("cyberai.cli.web3_audit.ScanSession"),
        patch("cyberai.cli.web3_audit.LLMClient"),
        patch("cyberai.cli.web3_audit.AuditLogger"),
        patch("cyberai.cli.web3_audit.SmartContractAgent", return_value=fake),
    ):
        return CliRunner().invoke(cli, ["web3", "audit", *args])


def test_audit_plain_output():
    res = _run(["contracts/Vault.sol"])
    assert res.exit_code == 0, res.output
    assert "Web3 audit" in res.output
    assert "reentrancy-eth" in res.output


def test_audit_immunefi_flag_renders_submissions():
    res = _run(["contracts/Vault.sol", "--immunefi"])
    assert res.exit_code == 0, res.output
    assert "**Severity:** Critical" in res.output
    assert "## Proof of Concept" in res.output
    assert "1500.000000 ETH" in res.output
    # two findings (poc + reentrancy) separated by a horizontal rule
    assert "---" in res.output


def test_audit_immunefi_no_findings():
    res = _run(["contracts/Clean.sol", "--immunefi"], result={"mode": "local"})
    assert res.exit_code == 0, res.output
    assert "No findings to report" in res.output


def test_audit_help_lists_command():
    res = CliRunner().invoke(cli, ["web3", "--help"])
    assert res.exit_code == 0
    assert "audit" in res.output
