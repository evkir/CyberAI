"""Tests for the unified OOB-confirm layer: confidence, confirm entry, mutation."""

from __future__ import annotations

from unittest.mock import MagicMock

from cyberai.agents.exploit.oob_workflow import OOBFinding, OOBWorkflow, confirm_oob
from cyberai.core.scan_session import ScanSession, Severity
from cyberai.integrations.oob_payloads import generate_ssrf_payloads, mutate_payloads
from cyberai.integrations.phantom_grid import OOBInteraction

_INTER = OOBInteraction(interaction_id="TOK", protocol="http", source_ip="1.2.3.4", timestamp="0")


def _grid():
    grid = MagicMock()
    grid.available = True
    grid.base_url = "http://grid:9090"
    grid.create_token.return_value = "TOK"
    return grid


def _poller(callbacks):
    poller = MagicMock()
    poller.wait_for_callback.side_effect = callbacks
    return poller


# ── confidence primitive ──────────────────────────────────────────────


def test_confidence_reflects_callback():
    confirmed = OOBFinding("ssrf", "TOK", "ssrf", confirmed=True, interaction=_INTER)
    missed = OOBFinding("ssrf", "TOK", "ssrf", confirmed=False)
    assert confirmed.confidence == 1.0
    assert missed.confidence == 0.0
    assert confirmed.to_dict()["confidence"] == 1.0
    assert missed.to_dict()["confidence"] == 0.0


# ── record -> session Finding ─────────────────────────────────────────


def test_record_confirmed_high_confidence():
    s = ScanSession(target="t")
    f = OOBFinding(
        "ssrf", "TOK", "ssrf", confirmed=True, interaction=_INTER, ai_analysis="proof"
    ).record(s)
    assert f.severity == Severity.HIGH
    assert f.confidence == 1.0
    assert f.description == "proof"
    assert "confirmed out-of-band" in f.title


def test_record_unconfirmed_zero_confidence():
    s = ScanSession(target="t")
    f = OOBFinding("sqli", "TOK", "sqli", confirmed=False).record(s)
    assert f.severity == Severity.INFO
    assert f.confidence == 0.0
    assert "not confirmed" in f.title
    assert "sqli" in f.description  # falls back to generic description


# ── mutate_payloads ───────────────────────────────────────────────────


def test_mutate_url_payload_variants():
    types = {m["type"] for m in mutate_payloads([{"type": "ssrf_http", "payload": "http://a/b"}])}
    assert "ssrf_http_urlenc" in types
    assert "ssrf_http_double_urlenc" in types
    assert "ssrf_http_at_embed" in types  # only for URLs with a scheme


def test_mutate_non_url_payload_no_at_embed():
    types = {m["type"] for m in mutate_payloads([{"type": "x", "payload": "a b/c?d=1"}])}
    assert types == {"x_urlenc", "x_double_urlenc"}


def test_mutate_skips_empty_and_dedups():
    assert mutate_payloads([{"type": "x", "payload": ""}]) == []
    p = {"type": "x", "payload": "http://a/b"}
    assert len(mutate_payloads([p, p])) == len(mutate_payloads([p]))  # deduped


def test_mutate_default_type_when_missing():
    out = mutate_payloads([{"payload": "http://a/b"}])
    assert all(m["type"].startswith("payload_") for m in out)


# ── run(): mutation retry round ───────────────────────────────────────


def test_run_confirms_on_mutated_after_base_miss():
    base = generate_ssrf_payloads("grid:9090", "TOK")
    poller = _poller([None] * len(base) + [_INTER])
    delivered: list = []
    finding = OOBWorkflow(grid=_grid(), poller=poller).run(
        "ssrf", deliver_fn=lambda p: delivered.append(p)
    )
    assert finding.confirmed is True
    assert finding.confidence == 1.0
    assert len(finding.payloads_tried) > len(base)  # mutation round ran
    assert len(delivered) == len(finding.payloads_tried)


def test_run_total_miss_unconfirmed():
    poller = _poller([None] * 100)
    finding = OOBWorkflow(grid=_grid(), poller=poller).run("ssrf", deliver_fn=lambda p: None)
    assert finding.confirmed is False
    assert finding.confidence == 0.0


def test_run_llm_analysis_failure_is_graceful():
    llm = MagicMock()
    llm.call.side_effect = RuntimeError("llm down")
    finding = OOBWorkflow(grid=_grid(), llm=llm, poller=_poller([_INTER])).run(
        "ssrf", deliver_fn=lambda p: None
    )
    assert finding.confirmed is True
    assert finding.ai_analysis == ""  # analysis failure swallowed


# ── confirm_oob unified entry ─────────────────────────────────────────


def test_confirm_oob_entry_confirms():
    finding = confirm_oob("xxe", deliver_fn=lambda p: None, grid=_grid(), poller=_poller([_INTER]))
    assert finding.confirmed is True
    assert finding.category == "xxe"


def test_confirm_oob_grid_unavailable():
    grid = MagicMock()
    grid.available = False
    grid.base_url = "http://grid:9090"
    finding = confirm_oob("ssrf", deliver_fn=lambda p: None, grid=grid, poller=MagicMock())
    assert finding.confirmed is False
    assert finding.error == "phantom-grid unavailable"
