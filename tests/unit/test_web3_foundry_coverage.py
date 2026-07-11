"""Coverage for anvil_harness and foundry_poc execution paths."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.agents.web3 import anvil_harness as ah
from cyberai.agents.web3 import foundry_poc as fp
from cyberai.agents.web3.anvil_harness import AnvilFork, find_anvil
from cyberai.agents.web3.foundry_poc import ForgePoCTool, find_forge, parse_forge_test_json


# ── find_* on PATH / fallback ─────────────────────────────────────────
def test_find_anvil_on_path(monkeypatch):
    monkeypatch.delenv("ANVIL_PATH", raising=False)
    with patch.object(ah.shutil, "which", return_value="/usr/bin/anvil"):
        assert find_anvil() == "/usr/bin/anvil"


def test_find_anvil_fallback(monkeypatch):
    monkeypatch.delenv("ANVIL_PATH", raising=False)
    with patch.object(ah.shutil, "which", return_value=None):
        with patch.object(ah.os.path, "exists", lambda p: p == ah._FALLBACK_PATHS[0]):
            assert find_anvil() == ah._FALLBACK_PATHS[0]


def test_find_forge_on_path(monkeypatch):
    monkeypatch.delenv("FORGE_PATH", raising=False)
    with patch.object(fp.shutil, "which", return_value="/usr/bin/forge"):
        assert find_forge() == "/usr/bin/forge"


def test_find_forge_fallback(monkeypatch):
    monkeypatch.delenv("FORGE_PATH", raising=False)
    with patch.object(fp.shutil, "which", return_value=None):
        with patch.object(fp.os.path, "exists", lambda p: p == fp._FALLBACK_PATHS[0]):
            assert find_forge() == fp._FALLBACK_PATHS[0]


# ── anvil start / stop paths ──────────────────────────────────────────
def _ready_log(tmp_path, text):
    log = tmp_path / "anvil.log"
    log.write_text(text)
    return log


def test_start_spawn_exception(tmp_path):
    fork = AnvilFork(anvil_path="/opt/anvil")
    with patch.object(ah.os.path, "exists", return_value=True):
        with patch.object(ah.subprocess, "Popen", side_effect=OSError("nope")):
            with patch.object(ah.tempfile, "NamedTemporaryFile") as ntf:
                ntf.return_value.name = str(tmp_path / "l.log")
                assert fork.start() is False


def test_start_ready_then_stop(tmp_path):
    log = _ready_log(tmp_path, "boot\nListening on 127.0.0.1:8545\n")
    proc = MagicMock()
    proc.poll.return_value = None
    fork = AnvilFork(anvil_path="/opt/anvil", port=8545, timeout=2)
    with patch.object(ah.os.path, "exists", return_value=True):
        with patch.object(ah.subprocess, "Popen", return_value=proc):
            with patch.object(ah.tempfile, "NamedTemporaryFile") as ntf:
                ntf.return_value.name = str(log)
                assert fork.start() is True
                assert fork.rpc_url == "http://127.0.0.1:8545"
                # stop() terminates a live proc and clears state.
                fork.stop()
                proc.terminate.assert_called_once()
                assert fork.rpc_url is None


def test_stop_kills_on_wait_timeout(tmp_path):
    proc = MagicMock()
    proc.poll.return_value = None
    proc.wait.side_effect = ah.subprocess.TimeoutExpired("anvil", 5)
    fork = AnvilFork(anvil_path="/opt/anvil")
    fork._proc = proc
    fork._log_path = None
    fork.stop()
    proc.kill.assert_called_once()


def test_start_timeout_no_ready(tmp_path):
    log = _ready_log(tmp_path, "no marker here\n")
    proc = MagicMock()
    proc.poll.return_value = None
    fork = AnvilFork(anvil_path="/opt/anvil", timeout=0)  # deadline in the past
    with patch.object(ah.os.path, "exists", return_value=True):
        with patch.object(ah.subprocess, "Popen", return_value=proc):
            with patch.object(ah.tempfile, "NamedTemporaryFile") as ntf:
                ntf.return_value.name = str(log)
                assert fork.start() is False


def test_start_process_dies(tmp_path):
    log = _ready_log(tmp_path, "crash\n")
    proc = MagicMock()
    proc.poll.return_value = 1  # already exited
    fork = AnvilFork(anvil_path="/opt/anvil", timeout=2)
    with patch.object(ah.os.path, "exists", return_value=True):
        with patch.object(ah.subprocess, "Popen", return_value=proc):
            with patch.object(ah.tempfile, "NamedTemporaryFile") as ntf:
                ntf.return_value.name = str(log)
                assert fork.start() is False


def test_cleanup_log_unlinks_real_file(tmp_path):
    log = tmp_path / "l.log"
    log.write_text("x")
    fork = AnvilFork(anvil_path=None)
    fork._log_path = str(log)
    fork._cleanup_log()
    assert not log.exists()
    assert fork._log_path is None


def test_cleanup_log_unlink_oserror(tmp_path, monkeypatch):
    log = tmp_path / "l.log"
    log.write_text("x")
    fork = AnvilFork(anvil_path=None)
    fork._log_path = str(log)
    with patch.object(ah.os, "unlink", side_effect=OSError("busy")):
        fork._cleanup_log()  # swallowed
    assert fork._log_path is None


def test_context_manager_real_enter_exit():
    with AnvilFork(anvil_path=None) as f:  # unavailable -> start no-op
        assert f.available is False
        assert f.rpc_url is None


# ── foundry parse / run edge paths ────────────────────────────────────
def test_parse_non_dict_suite_and_results():
    assert parse_forge_test_json('{"s": 123}') == []  # suite not a dict
    assert parse_forge_test_json('{"s": {"test_results": 5}}') == []  # results not a dict
    assert (
        parse_forge_test_json('{"s": {"test_results": {"testExploit()": 9}}}') == []
    )  # res not dict


def test_extract_profit_handles_non_list_and_non_str():
    report = (
        '{"s": {"test_results": {"testExploit()": {"status": "Success", "decoded_logs": null}}}}'
    )
    findings = parse_forge_test_json(report)
    assert len(findings) == 1 and findings[0].profit_wei == 0
    report2 = (
        '{"s": {"test_results": {"testExploit()": '
        '{"status": "Success", "decoded_logs": [123, "noise"]}}}}'
    )
    assert parse_forge_test_json(report2)[0].profit_wei == 0


def test_run_happy_path_no_rpc(tmp_path):
    tool = ForgePoCTool(forge_path="/opt/forge")
    proc = MagicMock()
    proc.stdout = '{"s": {"test_results": {"testExploit()": {"status": "Success"}}}}'
    with patch.object(fp.os.path, "exists", return_value=True):
        with patch.object(fp.subprocess, "run", return_value=proc) as run:
            findings = tool.run("proj")  # no rpc_url -> no --fork-url
            assert "--fork-url" not in run.call_args[0][0]
    assert len(findings) == 1


def test_run_timeout(tmp_path):
    tool = ForgePoCTool(forge_path="/opt/forge")
    with patch.object(fp.os.path, "exists", return_value=True):
        with patch.object(
            fp.subprocess, "run", side_effect=fp.subprocess.TimeoutExpired("forge", 1)
        ):
            assert tool.run("proj") == []


def test_run_generic_exception(tmp_path):
    tool = ForgePoCTool(forge_path="/opt/forge")
    with patch.object(fp.os.path, "exists", return_value=True):
        with patch.object(fp.subprocess, "run", side_effect=RuntimeError("boom")):
            assert tool.run("proj") == []


def test_start_read_oserror_then_ready():
    # First banner read raises OSError (swallowed), loop sleeps, second read is ready.
    proc = MagicMock()
    proc.poll.return_value = None
    reader = MagicMock()
    reader.read_text.side_effect = [OSError("io"), "Listening on 127.0.0.1:8545\n"]
    fork = AnvilFork(anvil_path="/opt/anvil", port=8545, timeout=2)
    with (
        patch.object(ah.os.path, "exists", return_value=True),
        patch.object(ah.subprocess, "Popen", return_value=proc),
        patch.object(ah.tempfile, "NamedTemporaryFile") as ntf,
        patch.object(ah, "Path", return_value=reader),
        patch.object(ah.time, "sleep", return_value=None),
    ):
        ntf.return_value.name = "/tmp/anvil-x.log"
        assert fork.start() is True
        assert fork.rpc_url == "http://127.0.0.1:8545"
    fork._proc = None
