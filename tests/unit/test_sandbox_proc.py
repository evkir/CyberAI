"""Sealed subprocess must not leak operator credentials to untrusted tools."""

import os
import subprocess
import sys

import pytest

from cyberai.core.sandbox import SealedEnvError, run_sealed, sealed_env

_DUMP = "import os,json;print(json.dumps(dict(os.environ)))"


@pytest.fixture
def poisoned_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-canary-openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-canary-anthropic")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "canary-aws")
    monkeypatch.setenv("HARMLESS_FLAG", "1")


def test_child_cannot_read_llm_keys(poisoned_env):
    import json

    proc = run_sealed([sys.executable, "-c", _DUMP], timeout=30)
    child_env = json.loads(proc.stdout)

    assert "OPENAI_API_KEY" not in child_env
    assert "ANTHROPIC_API_KEY" not in child_env
    assert "AWS_SECRET_ACCESS_KEY" not in child_env
    assert "canary" not in proc.stdout


def test_base_env_is_present(poisoned_env):
    env = sealed_env()
    assert env["PATH"]
    assert env["HOME"]


def test_allowlist_forwards_harmless_var(poisoned_env):
    env = sealed_env(allow=["HARMLESS_FLAG"])
    assert env["HARMLESS_FLAG"] == "1"


@pytest.mark.parametrize("name", ["OPENAI_API_KEY", "MY_TOKEN", "DB_PASSWORD", "WALLET_MNEMONIC"])
def test_allowlist_rejects_credential_shaped_names(name, poisoned_env):
    with pytest.raises(SealedEnvError):
        sealed_env(allow=[name])


def test_extra_env_rejects_credential_shaped_names():
    with pytest.raises(SealedEnvError):
        sealed_env(extra={"SOME_SECRET": "x"})


def test_string_argv_is_rejected():
    with pytest.raises(SealedEnvError):
        run_sealed("echo hi")  # type: ignore[arg-type]


def test_no_inherited_env_at_all(poisoned_env):
    import json

    proc = run_sealed([sys.executable, "-c", _DUMP], timeout=30)
    child_env = json.loads(proc.stdout)
    leaked = set(child_env) & set(os.environ) - {"PATH", "LANG", "LC_ALL", "TERM", "TZ", "HOME"}
    assert not leaked, f"unexpected inherited vars: {sorted(leaked)}"


def test_popen_child_cannot_read_llm_keys(poisoned_env):
    import json

    from cyberai.core.sandbox import popen_sealed

    proc = popen_sealed(
        [sys.executable, "-c", _DUMP], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, _ = proc.communicate(timeout=30)
    child_env = json.loads(out)

    assert "OPENAI_API_KEY" not in child_env
    assert "ANTHROPIC_API_KEY" not in child_env
    assert "canary" not in out


def test_popen_string_argv_is_rejected():
    from cyberai.core.sandbox import popen_sealed

    with pytest.raises(SealedEnvError):
        popen_sealed("echo hi")  # type: ignore[arg-type]


def test_run_sealed_forwards_stdin():
    """DEVNULL keeps interactive tools from reading the operator's terminal."""
    read_stdin = "import sys;sys.stdout.write(repr(sys.stdin.read()))"
    proc = run_sealed(
        [sys.executable, "-c", read_stdin],
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    assert proc.stdout == "''"


def test_operator_home_is_real_home():
    from pathlib import Path

    from cyberai.core.sandbox import operator_home

    assert operator_home() == Path.home()
