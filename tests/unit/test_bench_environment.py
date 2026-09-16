"""The toolchain probe reports what it measured and nothing else."""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

from cyberai.bench import environment as env


def _exe(path: Path, body: str) -> str:
    """Write an executable /bin/sh stub and return its path."""
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_the_first_line_decides_even_though_a_later_one_also_parses():
    """Measured `nmap --version`: line three names liblua 5.4.8.

    Both numbers are well-formed, so a probe that scanned lines in any other
    order would report the version of a library nmap links against.
    """
    stdout = (
        "Nmap version 7.98 ( https://nmap.org )\n"
        "Platform: x86_64-pc-linux-gnu\n"
        "Compiled with: liblua-5.4.8 openssl-3.5.5 libssh2-1.11.1\n"
    )
    assert env.parse_version(stdout, "") == "7.98"


def test_the_banner_nuclei_writes_to_stderr_is_read():
    # Measured on nuclei 3.8.0: stderr, colour codes, a 'v' before the number.
    stderr = "[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.8.0"
    assert env.parse_version("", stderr) == "3.8.0"


def test_stdout_is_read_before_stderr():
    assert env.parse_version("aderyn 0.1.9", "unrelated 9.9.9") == "0.1.9"


def test_a_line_carrying_no_dotted_number_is_not_a_version():
    assert env.parse_version("Usage: searchsploit [options] term", "") is None


def test_a_binary_that_is_absent_is_recorded_absent_not_guessed():
    got = env.probe_tool(env.ToolProbe("ghost", lambda: None, "--version"))
    assert (got.path, got.version, got.detail) == (None, None, env.NOT_INSTALLED)


def test_an_unmeasured_flag_means_the_binary_is_never_executed(tmp_path):
    marker = tmp_path / "it-ran"
    stub = _exe(tmp_path / "noflag", f"touch {marker}")
    got = env.probe_tool(env.ToolProbe("noflag", lambda: stub, None))
    assert got.path == stub
    assert got.version is None
    assert got.detail == env.FLAG_NOT_MEASURED
    assert not marker.exists()


def test_an_unparsed_answer_is_not_promoted_to_a_version(tmp_path):
    stub = _exe(tmp_path / "mute", "echo no numbers on this line")
    got = env.probe_tool(env.ToolProbe("mute", lambda: stub, "--version"))
    assert got.version is None
    assert got.detail == env.NOT_PARSED


def test_the_version_comes_from_the_path_the_resolver_returns(monkeypatch, tmp_path):
    """The env override decides which nmap runs, so it decides the version too.

    A probe reaching for shutil.which would answer with the system nmap and
    pass on any machine that has one -- the DR shape: green over a binary the
    run would not have used.
    """
    stub = _exe(tmp_path / "nmap", "echo 'Nmap version 9.99 ( https://nmap.org )'")
    monkeypatch.setenv("NMAP_PATH", stub)
    probe = next(p for p in env.TOOL_PROBES if p.name == "nmap")
    got = env.probe_tool(probe)
    assert got.path == stub
    assert got.version == "9.99"
    assert got.detail == ""


def test_a_failing_probe_is_reported_not_raised(monkeypatch):
    def boom(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(env, "run_sealed", boom)
    got = env.probe_tool(env.ToolProbe("slow", lambda: "/bin/true", "--version"))
    assert got.version is None
    assert got.detail.startswith("probe failed")


def test_every_probe_resolves_through_the_module_that_owns_the_tool():
    expected = {
        "nmap": ("cyberai.agents.recon.nmap_tool", "find_nmap"),
        "nuclei": ("cyberai.agents.exploit.nuclei_engine", "find_nuclei"),
        "searchsploit": ("cyberai.agents.exploit.searchsploit", "find_searchsploit"),
        "slither": ("cyberai.agents.web3.slither_tool", "find_slither"),
        "aderyn": ("cyberai.agents.web3.aderyn_tool", "find_aderyn"),
        "forge": ("cyberai.agents.web3.foundry_poc", "find_forge"),
        "anvil": ("cyberai.agents.web3.anvil_harness", "find_anvil"),
        "halmos": ("cyberai.agents.web3.halmos_tool", "find_halmos"),
        "mst": ("cyberai.agents.mcp_scan.mst_bridge", "find_mst"),
    }
    got = {p.name: (p.resolver.__module__, p.resolver.__name__) for p in env.TOOL_PROBES}
    assert got == expected


def test_the_toolchain_is_handed_over_immutable():
    """The manifest is frozen and fingerprints this; a list would be a
    shared reference into a record that claims to be immutable."""
    assert isinstance(env.probe_toolchain((env.ToolProbe("x", lambda: None, None),)), tuple)


def test_the_toolchain_is_probed_in_registry_order():
    probes = (
        env.ToolProbe("first", lambda: None, None),
        env.ToolProbe("second", lambda: None, None),
    )
    assert [v.name for v in env.probe_toolchain(probes)] == ["first", "second"]
