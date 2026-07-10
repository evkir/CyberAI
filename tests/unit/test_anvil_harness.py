"""Tests for the anvil mainnet-fork harness."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.agents.web3.anvil_harness import AnvilFork, find_anvil


def test_find_anvil_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "anvil"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("ANVIL_PATH", str(fake))
    assert find_anvil() == str(fake)


def test_unavailable_start_is_graceful(monkeypatch):
    monkeypatch.delenv("ANVIL_PATH", raising=False)
    with patch("cyberai.agents.web3.anvil_harness.shutil.which", return_value=None):
        with patch("cyberai.agents.web3.anvil_harness.os.path.exists", return_value=False):
            fork = AnvilFork(fork_url="http://rpc.example")
            assert fork.available is False
            with patch("cyberai.agents.web3.anvil_harness.subprocess.Popen") as popen:
                assert fork.start() is False
                assert fork.rpc_url is None
                popen.assert_not_called()


def test_build_cmd_includes_fork_and_block():
    fork = AnvilFork(
        fork_url="http://rpc.example",
        fork_block=12345,
        port=8600,
        anvil_path="/opt/anvil",
    )
    cmd = fork._build_cmd()
    assert cmd[0] == "/opt/anvil"
    assert "--port" in cmd and "8600" in cmd
    assert "--fork-url" in cmd and "http://rpc.example" in cmd
    assert "--fork-block-number" in cmd and "12345" in cmd


def test_start_detects_ready_banner(tmp_path, monkeypatch):
    # A live anvil prints "Listening on 127.0.0.1:<port>" once RPC is up.
    log = tmp_path / "anvil.log"
    log.write_text("anvil starting\nListening on 127.0.0.1:8545\n")

    proc = MagicMock()
    proc.poll.return_value = None  # still running

    fork = AnvilFork(anvil_path="/opt/anvil", port=8545, timeout=2)
    with patch("cyberai.agents.web3.anvil_harness.os.path.exists", return_value=True):
        with patch("cyberai.agents.web3.anvil_harness.subprocess.Popen", return_value=proc):
            with patch("cyberai.agents.web3.anvil_harness.tempfile.NamedTemporaryFile") as ntf:
                ntf.return_value.name = str(log)
                assert fork.start() is True
                assert fork.rpc_url == "http://127.0.0.1:8545"
    fork._proc = None  # avoid touching the MagicMock in stop()


def test_start_returns_false_if_process_dies(tmp_path, monkeypatch):
    log = tmp_path / "anvil.log"
    log.write_text("boom\n")  # no ready marker

    proc = MagicMock()
    proc.poll.return_value = 1  # exited immediately

    fork = AnvilFork(anvil_path="/opt/anvil", timeout=2)
    with patch("cyberai.agents.web3.anvil_harness.os.path.exists", return_value=True):
        with patch("cyberai.agents.web3.anvil_harness.subprocess.Popen", return_value=proc):
            with patch("cyberai.agents.web3.anvil_harness.tempfile.NamedTemporaryFile") as ntf:
                ntf.return_value.name = str(log)
                assert fork.start() is False
                assert fork.rpc_url is None


def test_context_manager_starts_and_stops():
    fork = AnvilFork(anvil_path=None)  # unavailable -> no-op start
    with patch.object(AnvilFork, "start", return_value=False) as start:
        with patch.object(AnvilFork, "stop") as stop:
            with fork as f:
                assert f is fork
            start.assert_called_once()
            stop.assert_called_once()
