"""OOB SSRF detection, mocked end-to-end against phantom-grid v2.0."""

from __future__ import annotations

from unittest.mock import MagicMock

from cyberai.agents.exploit.oob_workflow import OOBFinding, OOBWorkflow
from cyberai.integrations.phantom_grid import OOBInteraction, PhantomGridClient


def _grid(token: str, *, available: bool = True) -> MagicMock:
    """A mock PhantomGridClient (no wait_for_callback — that lives on poller)."""
    grid = MagicMock(spec=PhantomGridClient)
    grid.available = available
    grid.base_url = "http://grid.local:9090"
    grid.create_token.return_value = token
    grid.capture_url.return_value = f"http://grid.local:9090/c/{token}"
    grid.get_interactions.return_value = []
    return grid


def _poller(interaction):
    """A mock poller whose wait_for_callback yields the given interaction."""
    from cyberai.integrations.phantom_grid_poller import PhantomGridPoller

    poller = MagicMock(spec=PhantomGridPoller)
    poller.wait_for_callback.return_value = interaction
    return poller


def _callback(token: str) -> OOBInteraction:
    return OOBInteraction(
        interaction_id=token,
        protocol="http",
        source_ip="10.10.10.5",
        timestamp="2026-06-12T00:00:00Z",
        payload=f"/c/{token}",
    )


# ── confirmed path ────────────────────────────────────────────────────


def test_ssrf_confirmed_via_callback():
    token = "tok_ssrf_1"
    grid = _grid(token)
    wf = OOBWorkflow(grid=grid, poller=_poller(_callback(token)))

    delivered = []
    finding = wf.run("ssrf", deliver_fn=lambda p: delivered.append(p))

    assert isinstance(finding, OOBFinding)
    assert finding.confirmed is True
    assert finding.severity == "HIGH"
    assert finding.category == "ssrf"
    assert finding.token == token
    assert finding.interaction.source_ip == "10.10.10.5"
    # delivery was actually attempted before the callback confirmed
    assert len(delivered) >= 1


def test_ssrf_confirmed_stops_at_first_callback():
    token = "tok_ssrf_2"
    grid = _grid(token)
    wf = OOBWorkflow(grid=grid, poller=_poller(_callback(token)))

    delivered = []
    wf.run("ssrf", deliver_fn=lambda p: delivered.append(p))
    # first payload already triggers a callback -> only one delivery
    assert len(delivered) == 1


# ── not-confirmed path ────────────────────────────────────────────────


def test_ssrf_not_confirmed_when_no_callback():
    grid = _grid("tok_none")
    wf = OOBWorkflow(grid=grid, poller=_poller(None))

    delivered = []
    finding = wf.run("ssrf", deliver_fn=lambda p: delivered.append(p))

    assert finding.confirmed is False
    assert finding.severity == "INFO"
    # all ssrf payloads attempted, none confirmed
    assert len(delivered) == len(finding.payloads_tried) >= 1


# ── grid unavailable ──────────────────────────────────────────────────


def test_ssrf_grid_unavailable():
    grid = _grid("tok_x", available=False)
    wf = OOBWorkflow(grid=grid, poller=_poller(None))

    finding = wf.run("ssrf", deliver_fn=lambda p: None)
    assert finding.confirmed is False
    assert finding.error == "phantom-grid unavailable"
    grid.create_token.assert_not_called()


# ── delivery failure tolerated ────────────────────────────────────────


def test_ssrf_delivery_exception_continues():
    token = "tok_err"
    grid = _grid(token)
    wf = OOBWorkflow(grid=grid, poller=_poller(None))

    def boom(_payload):
        raise RuntimeError("target unreachable")

    finding = wf.run("ssrf", deliver_fn=boom)
    # workflow swallows delivery errors and finishes unconfirmed
    assert finding.confirmed is False


# ── LLM analysis on confirm ───────────────────────────────────────────


def test_ssrf_confirmed_triggers_llm_analysis():
    token = "tok_llm"
    grid = _grid(token)
    llm = MagicMock()
    llm.call.return_value = "SSRF confirmed: HTTP callback proves server-side fetch."
    wf = OOBWorkflow(grid=grid, llm=llm, poller=_poller(_callback(token)))

    finding = wf.run("ssrf", deliver_fn=lambda p: None)
    assert finding.confirmed is True
    assert "SSRF confirmed" in finding.ai_analysis
    llm.call.assert_called_once()


# ── correlate ─────────────────────────────────────────────────────────


def test_correlate_matches_token():
    wf = OOBWorkflow(grid=_grid("tok_x"), poller=_poller(None))
    i = _callback("tok_x")
    assert wf.correlate("tok_x", [i]) is i


def test_correlate_empty_returns_none():
    wf = OOBWorkflow(grid=_grid("tok_x"), poller=_poller(None))
    assert wf.correlate("tok_x", []) is None
