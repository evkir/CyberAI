"""Tests for the bench success-criteria evaluator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cyberai.bench.evaluator import (
    cmdi_solved_from_evidence,
    evaluate,
    probe_cmdi,
    probe_sqli,
    probe_traversal,
    sqli_solved_from_evidence,
    traversal_solved_from_evidence,
)
from cyberai.bench.targets import LOCAL_SUITE, VulnClass, VulnTarget


def _target(vc: VulnClass) -> VulnTarget:
    return next(t for t in LOCAL_SUITE if t.vuln_class is vc)


def test_sqli_marker_detection():
    assert sqli_solved_from_evidence('{"flag": "FLAG{sqli-auth-bypass}"}') is True
    assert sqli_solved_from_evidence('{"status": "denied"}') is False


def test_cmdi_requires_injected_marker():
    assert cmdi_solved_from_evidence("uid=0(root) TOKEN42", "TOKEN42") is True
    assert cmdi_solved_from_evidence("64 bytes from 127.0.0.1", "TOKEN42") is False
    assert cmdi_solved_from_evidence("anything", "") is False


def test_traversal_requires_secret_token():
    assert traversal_solved_from_evidence("root:x:0:0:secretz", "secretz") is True
    assert traversal_solved_from_evidence("<html>index</html>", "secretz") is False


def test_evaluate_dispatch_per_class():
    assert evaluate(_target(VulnClass.SQLI), "FLAG{sqli-auth-bypass}") is True
    assert evaluate(_target(VulnClass.COMMAND_INJECTION), "x TOK", marker="TOK") is True
    assert evaluate(_target(VulnClass.PATH_TRAVERSAL), "data SEC", marker="SEC") is True


def test_evaluate_unknown_class_is_unsolved():
    t = VulnTarget(
        id="z",
        name="z",
        vuln_class=VulnClass.SSRF,
        cwe="CWE-918",
        port=9009,
        app="ssrf",
        success_signal="oob",
    )
    assert evaluate(t, "anything") is False


def test_probe_sqli_mocked_success():
    resp = MagicMock(text='{"flag": "FLAG{sqli-auth-bypass}"}')
    client = MagicMock()
    client.__enter__.return_value.post.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_sqli("http://localhost:8801") is True


def test_probe_sqli_mocked_http_error():
    import httpx

    client = MagicMock()
    client.__enter__.return_value.post.side_effect = httpx.ConnectError("down")
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_sqli("http://localhost:8801") is False


def test_probe_cmdi_mocked_success():
    resp = MagicMock(text='{"output": "PING 127.0.0.1 ...\\n20571\\n"}')
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_cmdi("http://localhost:8802") is True


def test_probe_cmdi_rejects_reflected_payload():
    """A hardened target echoing the raw request must never count as solved."""
    resp = MagicMock(text="404 not found: 127.0.0.1; echo $((6857*3))")
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_cmdi("http://localhost:8802") is False


def test_probe_cmdi_mocked_http_error():
    import httpx

    client = MagicMock()
    client.__enter__.return_value.get.side_effect = httpx.ConnectError("down")
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_cmdi("http://localhost:8802") is False


def test_probe_traversal_mocked_success():
    resp = MagicMock(text="FLAG{path-traversal-file-read}")
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_traversal("http://localhost:8803") is True


def test_probe_traversal_rejects_reflected_filename():
    """Echoing the requested path back must never count as a file read."""
    resp = MagicMock(text="404 not found: ../../../../etc/bench_flag")
    client = MagicMock()
    client.__enter__.return_value.get.return_value = resp
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_traversal("http://localhost:8803") is False


def test_probe_traversal_mocked_http_error():
    import httpx

    client = MagicMock()
    client.__enter__.return_value.get.side_effect = httpx.ConnectError("down")
    with patch("cyberai.bench.evaluator.httpx.Client", return_value=client):
        assert probe_traversal("http://localhost:8803") is False
