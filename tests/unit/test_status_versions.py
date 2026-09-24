"""`status --versions` asks the tools, and plain `status` asks nothing.

Two halves of one contract. The flag exists because a probe starts a process
per located tool and status is the command an operator runs when something is
already wrong; a default that pays that cost would be the defect the flag was
added to avoid. So the cheap path has to stay provably cheap: the assertion is
that no process starts, not that the output looks the same.
"""

from __future__ import annotations

import ast
import pathlib

from click.testing import CliRunner

from cyberai import __main__ as main
from cyberai.bench import environment as env
from cyberai.bench.run_manifest import ToolVersion

# The one probe the fake answers for with no path, so that the found half and
# the missing half of the display cannot both be right by construction.
_ABSENT = "halmos"


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
    """The reading is asserted where it is produced, not where it is wrapped."""
    stub = tmp_path / "nmap"
    stub.write_text("#!/bin/sh\necho 'Nmap version 7.98 ( https://nmap.org )'\n")
    stub.chmod(0o755)
    monkeypatch.setenv("NMAP_PATH", str(stub))
    found, _ = main._toolchain_lines(versions=True)
    assert "nmap 7.98" in found


def test_a_located_tool_with_no_flag_says_so_rather_than_guessing(tmp_path, monkeypatch) -> None:
    """searchsploit and mas-sentry carry flag=None: no version was ever measured.

    Asserted against the line the command builds, not against the panel it
    prints. Rich wraps the rendered panel at the console width, and the found
    half is one comma-separated run of every located tool, so the wrap point
    is decided by how many binaries happen to be installed on the machine
    running the suite. On a host with the whole toolchain present the break
    lands inside this very phrase and the assertion fails on a tree that is
    correct; on a host missing one tool it lands elsewhere and passes for no
    better reason. A test whose verdict is a function of the operator's PATH
    measures the machine instead of the product.
    """
    stub = tmp_path / "searchsploit"
    stub.write_text("#!/bin/sh\necho 'Usage: searchsploit'\n")
    stub.chmod(0o755)
    monkeypatch.setenv("SEARCHSPLOIT_PATH", str(stub))
    found, _ = main._toolchain_lines(versions=True)
    assert f"searchsploit ({env.FLAG_NOT_MEASURED})" in found


def test_the_screen_names_the_source_of_the_one_control_that_defaults_on() -> None:
    """strict_scope is the only control here whose default is on.

    Every other line on the panel defaults to off, where "off (default)"
    answers nothing. This one ends a run before the first phase, so "off"
    has to say who turned it off.
    """
    runner = CliRunner()
    assert "Strict scope: on (default)" in runner.invoke(main.cli, ["status"]).output


def test_a_variable_that_is_set_is_named_even_when_it_is_empty(monkeypatch) -> None:
    """Set-ness is a fact about the environment; the value is a separate one.

    Truthiness here would report an empty variable as the default, which is
    the panel answering a question about a value when the question was about
    the environment. Measured while adding this line: an empty
    CYBERAI_STRICT_SCOPE turns the refusal off, because _env_bool treats an
    empty string as a chosen no while _env_int and _env_float treat it as
    nobody choosing. The panel has to name the variable in that case or the
    operator has no way to see it.
    """
    monkeypatch.setenv("CYBERAI_STRICT_SCOPE", "")
    output = CliRunner().invoke(main.cli, ["status"]).output
    assert "(CYBERAI_STRICT_SCOPE)" in output


def test_a_zero_budget_reads_as_disabled_rather_than_as_no_money(monkeypatch) -> None:
    monkeypatch.delenv("CYBERAI_MAX_COST_USD", raising=False)
    assert "Cost budget: disabled" in CliRunner().invoke(main.cli, ["status"]).output
    monkeypatch.setenv("CYBERAI_MAX_COST_USD", "5")
    assert "Cost budget: 5.0 USD" in CliRunner().invoke(main.cli, ["status"]).output


def test_every_field_the_orchestrator_reads_reaches_the_screen() -> None:
    """The screen shows what governs the run, checked against the run.

    Not a hand-written list: the fields are scanned out of orchestrator.py,
    so a control added there without a line here fails. Four fields on
    CyberAIConfig are read by nobody at all -- intel, timeout, verbose,
    use_lab_dogfood -- and a rule written as "every field" would have
    demanded a line for a lever that moves nothing.
    """
    root = pathlib.Path(__file__).resolve().parents[2]
    tree = ast.parse((root / "cyberai" / "core" / "orchestrator.py").read_text())
    read: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
            and node.value.attr == "config"
        ):
            read.add(node.attr)

    # field on CyberAIConfig -> the label that stands for it on the panel
    shown = {
        "air_gapped": "Air-gapped",
        "enable_planner": "Planner",
        "enable_replan": "Replan",
        "llm": "Provider",
        "max_cost_usd": "Cost budget",
        "output_dir": "Output",
        "routing": "Model routing",
        "strict_scope": "Strict scope",
        "use_planned_redteam": "Planned redteam",
        "use_web_recon": "Web recon",
    }
    assert read == set(shown), (
        f"orchestrator reads but the map does not name: {read - set(shown)}; "
        f"the map names what the orchestrator no longer reads: {set(shown) - read}"
    )

    output = CliRunner().invoke(main.cli, ["status"]).output
    for field, label in shown.items():
        assert f"{label}:" in output, f"{field} governs the run and has no line"


def test_the_probe_budget_is_shorter_than_the_manifest_budget() -> None:
    """Three minutes of hung binaries is not an answer to "what is wrong"."""
    assert env.STATUS_VERSION_TIMEOUT < env.VERSION_TIMEOUT


def test_one_pass_decides_both_halves(monkeypatch) -> None:
    """Found and missing come from the same probe result, not two walks.

    Two walks over the resolvers can disagree, and a display that disagrees
    with itself is the defect this file's sibling commit removed between the
    CLI and the run manifest.

    One probe answers with no path, so the two halves disagree about it.
    An earlier revision handed every probe a path and asserted that nothing
    was missing -- true of the code as written and equally true of a version
    that never looks at path at all, which mutation confirmed by emptying
    the missing half and watching this test pass. An assertion is only a
    check where its input tells the two apart.
    """
    resolved: list[str] = []
    probed: list[str] = []

    def probe(probes=env.TOOL_PROBES, **kwargs: object):  # type: ignore[no-untyped-def]
        probed.append("once")
        return tuple(
            ToolVersion(p.name, None, None, env.NOT_INSTALLED)
            if p.name == _ABSENT
            else ToolVersion(p.name, "/somewhere/" + p.name, "1.0", "")
            for p in probes
        )

    monkeypatch.setattr(main, "probe_toolchain", probe)
    monkeypatch.setattr(
        main,
        "_TOOLCHAIN",
        {name: (lambda n=name: resolved.append(n) or None) for name in dict(main._TOOLCHAIN)},
    )
    result = CliRunner().invoke(main.cli, ["status", "--versions"])

    assert probed == ["once"]
    assert resolved == [], f"a second walk asked the resolvers again: {resolved}"
    assert f"Tools missing: {_ABSENT}" in result.output
