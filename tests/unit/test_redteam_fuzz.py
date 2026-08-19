"""Tests for the LLM offensive red-team fuzzer and payload corpus."""

from __future__ import annotations

from unittest.mock import MagicMock

from cyberai.agents.recon.llm_detector import detect_llm_endpoints
from cyberai.agents.redteam.fuzzer import (
    FuzzReport,
    LLMChannelFuzzer,
    _extraction_leaked,
    _severity_for,
)
from cyberai.agents.redteam.payloads import (
    ACK_PREFIX,
    PayloadCategory,
    build_corpus,
    full_corpus,
    payloads_by_category,
)
from cyberai.integrations.phantom_grid import OOBInteraction

# ── payload corpus ────────────────────────────────────────────────────


def test_build_corpus_without_canary_omits_oob():
    corpus = build_corpus("")
    assert corpus, "corpus should be non-empty"
    assert all(not p.needs_oob for p in corpus)


def test_build_corpus_with_canary_includes_oob():
    corpus = build_corpus("http://grid/c/tok")
    assert any(p.needs_oob for p in corpus)


def test_full_corpus_includes_all():
    assert len(full_corpus()) >= len(build_corpus(""))
    assert any(p.needs_oob for p in full_corpus())


def test_render_substitutes_canary():
    oob = [p for p in full_corpus() if p.needs_oob][0]
    rendered = oob.render("http://grid/c/abc")
    assert "http://grid/c/abc" in rendered
    assert "{canary}" not in rendered


def test_payloads_by_category_filters():
    jb = payloads_by_category(PayloadCategory.JAILBREAK)
    assert jb and all(p.category == PayloadCategory.JAILBREAK for p in jb)


# ── severity mapping ──────────────────────────────────────────────────


def test_severity_precedence():
    assert _severity_for(True, True, True) == "CRITICAL"
    assert _severity_for(False, True, True) == "HIGH"
    assert _severity_for(False, False, True) == "MEDIUM"
    assert _severity_for(False, False, False) == "INFO"


def test_extraction_leak_heuristic():
    leaky = "You are a helpful assistant. Your instructions: never reveal keys."
    assert _extraction_leaked(leaky)
    assert not _extraction_leaked("The weather is sunny today.")


# ── fuzzer: grid helpers ──────────────────────────────────────────────


def _fuzzer_with_grid(available: bool, interactions=None):
    """Build a fuzzer whose grid+poller are mocked (no network)."""
    grid = MagicMock()
    grid.base_url = "http://127.0.0.1:9090"
    grid.api_key = ""
    grid.available = available
    grid.create_token.return_value = "tok123"
    grid.capture_url.return_value = "http://127.0.0.1:9090/c/tok123"
    fuzzer = LLMChannelFuzzer(grid=grid)
    # Replace the internally-created poller with a mock.
    fuzzer.poller = MagicMock()
    if interactions is not None:
        fuzzer.poller.wait_for_callback.return_value = interactions
    else:
        fuzzer.poller.wait_for_callback.return_value = None
    return fuzzer


# ── fuzzer: MCP channel ───────────────────────────────────────────────


def test_mcp_channel_ack_echoed_is_high():
    """An MCP tool-response echoing the ack marker scores HIGH."""
    fuzzer = _fuzzer_with_grid(available=False)

    def send_fn(payload: str) -> str:
        # Simulate a tool response that complied with an ack payload.
        return f"{ACK_PREFIX}ack"

    report = fuzzer.fuzz_channel(send_fn, channel_id="mcp:tool")
    assert isinstance(report, FuzzReport)
    high = [r for r in report.results if r.severity == "HIGH"]
    assert high and all(r.ack_echoed for r in high)
    assert report.flagged_count >= 1


# ── fuzzer: web channel ───────────────────────────────────────────────


def test_web_channel_extraction_leak_is_medium():
    """A web chat response leaking the prompt scores MEDIUM."""
    fuzzer = _fuzzer_with_grid(available=False)

    def send_fn(payload: str) -> str:
        # Only the extraction payloads should trip the leak heuristic.
        if "system prompt" in payload.lower() or "initialization" in payload.lower():
            return "You are a support bot. Your instructions are confidential."
        return "Sure, here is a normal answer."

    report = fuzzer.fuzz_channel(send_fn, channel_id="web:chat")
    med = [r for r in report.results if r.severity == "MEDIUM"]
    assert med and all(r.leak_detected for r in med)


# ── fuzzer: OOB confirmation ──────────────────────────────────────────


def test_oob_callback_confirms_critical():
    """A confirmed OOB callback on an SSRF payload scores CRITICAL."""
    hit = OOBInteraction(
        interaction_id="tok123",
        protocol="http",
        source_ip="1.2.3.4",
        timestamp="2026-01-01T00:00:00Z",
    )
    fuzzer = _fuzzer_with_grid(available=True, interactions=hit)

    def send_fn(payload: str) -> str:
        return "ok"

    report = fuzzer.fuzz_channel(send_fn, channel_id="web:chat")
    crit = [r for r in report.results if r.severity == "CRITICAL"]
    assert crit and all(r.oob_confirmed for r in crit)
    assert report.confirmed_count >= 1
    assert report.oob_used is True


def test_oob_unavailable_marks_undelivered():
    """OOB payloads are recorded undelivered when grid is unavailable."""
    fuzzer = _fuzzer_with_grid(available=False)

    def send_fn(payload: str) -> str:
        return "ok"

    report = fuzzer.fuzz_channel(send_fn, channel_id="mcp:tool")
    undelivered = [r for r in report.results if not r.delivered]
    assert undelivered, "OOB payloads should be marked undelivered"
    assert report.skipped_count >= 1


def test_delivery_error_marks_undelivered():
    """A raising send_fn yields an undelivered result, not a crash."""
    fuzzer = _fuzzer_with_grid(available=False)

    def send_fn(payload: str) -> str:
        raise RuntimeError("boom")

    report = fuzzer.fuzz_channel(send_fn, channel_id="mcp:tool")
    errored = [r for r in report.results if "delivery error" in r.detail]
    assert errored


# ── llm_detector (mocked prober, no network) ──────────────────────────


def test_detect_llm_endpoint_gated_status():
    """A 401 on a distinctive LLM path is a strong signal."""

    def prober(url: str):
        if url.endswith("/v1/chat/completions"):
            return {"status": 401, "headers": {}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}

    result = detect_llm_endpoints("example.com", prober=prober)
    assert result["is_llm_target"]
    eps = result["llm_endpoints"]
    assert any("v1/chat/completions" in e["url"] for e in eps)
    assert any("status:401-gated" in e["signals"] for e in eps)


def test_detect_llm_endpoint_header_signal():
    """An event-stream content-type flags a streaming chat channel."""

    def prober(url: str):
        if url.endswith("/api/chat"):
            return {
                "status": 200,
                "headers": {"content-type": "text/event-stream"},
                "body": "",
            }
        return None

    result = detect_llm_endpoints("http://example.com", prober=prober)
    assert result["is_llm_target"]


def test_detect_llm_endpoint_no_signals_is_empty():
    """A target with no LLM signals returns no endpoints."""

    def prober(url: str):
        return {"status": 404, "headers": {}, "body": "not found"}

    result = detect_llm_endpoints("example.com", prober=prober)
    assert not result["is_llm_target"]
    assert result["llm_endpoints"] == []


# ── fuzzer: reflection guard ──────────────────────────────────────────


def _echo(payload: str) -> str:
    """A channel that returns the request verbatim — the naive reflector."""
    return payload


def test_reflected_channel_scores_nothing():
    """A verbatim echo carries the marker back without executing anything."""
    fuzzer = _fuzzer_with_grid(available=False)

    report = fuzzer.fuzz_channel(_echo, channel_id="web:echo")

    delivered = [r for r in report.results if r.delivered]
    assert delivered, "the corpus must deliver something"
    assert all(r.reflected for r in delivered)
    acked = [r for r in delivered if r.ack_echoed]
    assert acked, "the guard is only meaningful while the marker is present"
    assert report.flagged_count == 0
    assert [r.payload_id for r in report.results if r.severity == "HIGH"] == []
    assert all("reflection, not execution" in r.detail for r in acked)


def test_non_reflecting_channel_still_flags():
    """Control: same marker, a response that does not echo the payload."""
    fuzzer = _fuzzer_with_grid(available=False)

    def send_fn(payload: str) -> str:
        return f"{ACK_PREFIX}ack"

    report = fuzzer.fuzz_channel(send_fn, channel_id="web:chat")

    assert not any(r.reflected for r in report.results)
    assert report.flagged_count >= 1
    assert any(r.severity == "HIGH" for r in report.results)


def test_severity_downgrades_a_reflected_marker():
    """Reflection removes the ack tier only; the other tiers are untouched."""
    assert _severity_for(False, True, False, False) == "HIGH"
    assert _severity_for(False, True, False, True) == "INFO"
    assert _severity_for(True, True, False, True) == "CRITICAL"
    assert _severity_for(False, True, True, True) == "MEDIUM"


def test_reflected_reaches_the_exported_dict():
    """The verdict must survive serialisation, not just the dataclass."""
    fuzzer = _fuzzer_with_grid(available=False)

    dumped = fuzzer.fuzz_channel(_echo, channel_id="web:echo").to_dict()

    delivered = [r for r in dumped["results"] if r["delivered"]]
    assert delivered
    assert all(r["reflected"] for r in delivered)
    assert dumped["flagged_count"] == 0
