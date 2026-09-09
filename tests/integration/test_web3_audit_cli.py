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


def _merged_result() -> dict:
    """A local run as the agent really shapes it: every bucket populated."""
    return {
        "mode": "local",
        "highest_severity": "Critical",
        "findings": [{"check": "controlled-delegatecall", "immunefi_severity": "Critical"}],
        "aderyn_findings": [
            {"check": "delegate-call-unchecked-address", "immunefi_severity": "Critical"},
            {"check": "send-ether-no-checks", "immunefi_severity": "High"},
        ],
        "merged_findings": [
            {
                "check": "controlled-delegatecall",
                "swc": "SWC-112",
                "immunefi_severity": "Critical",
                "confidence": "cross-validated",
                "sources": ["aderyn", "slither"],
            },
            {
                "check": "send-ether-no-checks",
                "swc": "SWC-105",
                "immunefi_severity": "High",
                "confidence": "single-tool",
                "sources": ["aderyn"],
            },
        ],
        # The shape analyze_source really produces: impact/confidence, and no
        # serialized tier at all (rule 90).
        "access_findings": [
            {
                "check": "missing-auth",
                "impact": "High",
                "confidence": "High",
                "contract": "Vault",
                "function": "setOwner",
                "source": "access-control",
            }
        ],
        "escalation_paths": [
            {
                "entry": "setOwner",
                "grants": "ownership",
                "unlocks": ["withdrawAll"],
                "source": "access-control",
            }
        ],
    }


def test_audit_prints_every_bucket_not_just_slither():
    res = _run(["contracts/Vault.sol"], result=_merged_result())
    assert res.exit_code == 0, res.output
    # short tokens: rich wraps these lines (rule 100)
    assert "send-ether-no-checks" in res.output
    assert "SWC-105" in res.output
    assert "cross-validated" in res.output
    assert "setOwner" in res.output
    assert "escalation" in res.output
    assert "withdrawAll" in res.output


def test_access_findings_are_classified_not_read_from_a_missing_key():
    """access dicts carry no tier; printing one requires classifying it."""
    res = _run(["contracts/Vault.sol"], result=_merged_result())
    line = next(x for x in res.output.splitlines() if "missing-auth" in x)
    assert "Critical" in line
    assert "Insight" not in line


def test_audit_prints_both_counts():
    res = _run(["contracts/Vault.sol"], result=_merged_result())
    out = res.output.replace("\n", " ")
    assert "aderyn 2" in out
    assert "swc groups: 2" in out


def test_audit_without_merge_still_prints_slither():
    res = _run(["contracts/Vault.sol"])
    assert res.exit_code == 0, res.output
    assert "reentrancy-eth" in res.output


def _ctx_run(args: list[str]):
    """Invoke the CLI and return the context the agent was called with."""
    fake = MagicMock()
    fake.run.return_value = _merged_result()
    with (
        patch("cyberai.cli.web3_audit.CyberAIConfig"),
        patch("cyberai.cli.web3_audit.ScanSession"),
        patch("cyberai.cli.web3_audit.LLMClient"),
        patch("cyberai.cli.web3_audit.AuditLogger"),
        patch("cyberai.cli.web3_audit.SmartContractAgent", return_value=fake),
    ):
        res = CliRunner().invoke(cli, ["web3", "audit", *args])
    return res, fake.run.call_args


def test_foundry_options_reach_the_agent(tmp_path):
    """Without this the PoC runner is unreachable: agent.run got no context."""
    res, call = _ctx_run(
        [
            "contracts/Vault.sol",
            "--foundry-project",
            str(tmp_path),
            "--fork-rpc",
            "http://127.0.0.1:8545",
            "--poc-match",
            "testDrain",
        ]
    )
    assert res.exit_code == 0, res.output
    ctx = call.kwargs["context"]
    assert ctx["foundry_project"] == str(tmp_path)
    assert ctx["fork_rpc"] == "http://127.0.0.1:8545"
    assert ctx["poc_match"] == "testDrain"


def test_halmos_options_reach_the_agent(tmp_path):
    res, call = _ctx_run(
        ["contracts/Vault.sol", "--halmos-project", str(tmp_path), "--halmos-contract", "VSymTest"]
    )
    assert res.exit_code == 0, res.output
    ctx = call.kwargs["context"]
    assert ctx["halmos_project"] == str(tmp_path)
    assert ctx["halmos_contract"] == "VSymTest"


def test_no_project_means_no_stray_knobs():
    """poc_match and halmos_loop have defaults; alone they are not a request."""
    res, call = _ctx_run(["contracts/Vault.sol"])
    assert res.exit_code == 0, res.output
    assert call.kwargs["context"] == {}


def test_poc_finding_is_printed_with_profit():
    result = _merged_result()
    result["poc_findings"] = [
        {
            "check": "onchain-poc-exploit",
            "test": "testExploit()",
            "confirmed": True,
            "profit_wei": 3 * 10**18,
        }
    ]
    fake = MagicMock()
    fake.run.return_value = result
    with (
        patch("cyberai.cli.web3_audit.CyberAIConfig"),
        patch("cyberai.cli.web3_audit.ScanSession"),
        patch("cyberai.cli.web3_audit.LLMClient"),
        patch("cyberai.cli.web3_audit.AuditLogger"),
        patch("cyberai.cli.web3_audit.SmartContractAgent", return_value=fake),
    ):
        res = CliRunner().invoke(cli, ["web3", "audit", "contracts/Vault.sol"])
    assert res.exit_code == 0, res.output
    out = res.output.replace("\n", " ")
    assert "testExploit()" in out
    assert "confirmed" in out
    assert "3.000000 ETH" in out
