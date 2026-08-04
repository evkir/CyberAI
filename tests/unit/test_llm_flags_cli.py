"""The two LLM flags must survive the trip from argv to config.

The table in test_cli_feature_flags.py calls _apply_feature_overrides
directly, which passes even when no click option is declared for the
keyword. These cases go through argv so a missing or misnamed option fails.
"""

import pytest
from click.testing import CliRunner

from cyberai.__main__ import scan

CLI_FLAGS = [
    ("--native-tools", "use_native_tools"),
    ("--llm-summary", "use_llm_summary"),
]
IDS = [f[0] for f in CLI_FLAGS]


@pytest.mark.parametrize("flag,attr", CLI_FLAGS, ids=IDS)
def test_option_is_declared(flag, attr):
    result = CliRunner().invoke(scan, ["--help"])
    assert result.exit_code == 0
    assert flag in result.output


@pytest.mark.parametrize("flag,attr", CLI_FLAGS, ids=IDS)
def test_flag_reaches_config(flag, attr, monkeypatch):
    seen = {}

    def _capture(config, target, authorized_scope=None, **kwargs):
        seen[attr] = getattr(config, attr)
        raise SystemExit(0)

    monkeypatch.setattr(
        "cyberai.__main__.Orchestrator",
        lambda config, phases=None, dry_run=False: _capture(config, None),
    )
    CliRunner().invoke(scan, ["example.com", "--dry-run", flag])
    assert seen[attr] is True
