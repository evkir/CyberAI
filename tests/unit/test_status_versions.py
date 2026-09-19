"""`status --versions` asks the tools, and plain `status` asks nothing.

Two halves of one contract. The flag exists because a probe starts a process
per located tool and status is the command an operator runs when something is
already wrong; a default that pays that cost would be the defect the flag was
added to avoid. So the cheap path has to stay provably cheap: the assertion is
that no process starts, not that the output looks the same.
"""

from __future__ import annotations

from click.testing import CliRunner

from cyberai import __main__ as main
from cyberai.bench import environment as env
from cyberai.bench.run_manifest import ToolVersion


def test_plain_status_starts_no_process(tmp_path, monkeypatch) -> None:
    """A tool has to be found before "nothing ran" means anything.

    The first version of this test patched run_sealed on a machine with no
    tools installed: the probe returned "not installed" before reaching any
    process, so the assertion held whatever the code did. Mutating the flag
    to probe unconditionally left it green. The stub below makes the binary
    resolvable, so a probe would reach run_sealed and the assertion has
    something to fail on.
    """
    stub = tmp_path / "nmap"
    stub.write_text("#!/bin/sh\necho 'Nmap version 7.98 ( https://nmap.org )'\n")
    stub.chmod(0o755)
    monkeypatch.setenv("NMAP_PATH", str(stub))

    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("status ran a binary without --versions")

    monkeypatch.setattr(env, "run_sealed", boom)
    result = CliRunner().invoke(main.cli, ["status"])
    assert result.exit_code == 0
    assert "nmap" in result.output


def test_the_flag_reports_the_version_the_tool_prints(tmp_path, monkeypatch) -> None:
    stub = tmp_path / "nmap"
    stub.write_text("#!/bin/sh\necho 'Nmap version 7.98 ( https://nmap.org )'\n")
    stub.chmod(0o755)
    monkeypatch.setenv("NMAP_PATH", str(stub))
    result = CliRunner().invoke(main.cli, ["status", "--versions"])
    assert "nmap 7.98" in result.output


def test_a_located_tool_with_no_flag_says_so_rather_than_guessing(tmp_path, monkeypatch) -> None:
    """searchsploit and mas-sentry carry flag=None: no version was ever measured."""
    stub = tmp_path / "searchsploit"
    stub.write_text("#!/bin/sh\necho 'Usage: searchsploit'\n")
    stub.chmod(0o755)
    monkeypatch.setenv("SEARCHSPLOIT_PATH", str(stub))
    result = CliRunner().invoke(main.cli, ["status", "--versions"])
    assert f"searchsploit ({env.FLAG_NOT_MEASURED})" in result.output


def test_the_probe_budget_is_shorter_than_the_manifest_budget() -> None:
    """Three minutes of hung binaries is not an answer to "what is wrong"."""
    assert env.STATUS_VERSION_TIMEOUT < env.VERSION_TIMEOUT


def test_one_pass_decides_both_halves(monkeypatch) -> None:
    """Found and missing come from the same probe result, not two walks.

    Two walks over the resolvers can disagree, and a display that disagrees
    with itself is the defect this file's sibling commit removed between the
    CLI and the run manifest.
    """
    resolved: list[str] = []
    probed: list[str] = []

    def probe(probes=env.TOOL_PROBES, **kwargs: object):  # type: ignore[no-untyped-def]
        probed.append("once")
        return tuple(ToolVersion(p.name, "/somewhere/" + p.name, "1.0", "") for p in probes)

    monkeypatch.setattr(main, "probe_toolchain", probe)
    monkeypatch.setattr(
        main,
        "_TOOLCHAIN",
        {name: (lambda n=name: resolved.append(n) or None) for name in dict(main._TOOLCHAIN)},
    )
    result = CliRunner().invoke(main.cli, ["status", "--versions"])

    assert probed == ["once"]
    assert resolved == [], f"a second walk asked the resolvers again: {resolved}"
    assert "Tools missing: none" in result.output
