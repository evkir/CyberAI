"""Tests for HTTP attack-surface discovery."""

from __future__ import annotations

import json

from cyberai.agents.recon.web_surface import discover_surface, normalize_base

_INDEX = """
<html><body>
  <a href="/search?q=test">search</a>
  <a href="https://evil.example.com/out">offsite</a>
  <form action="/login" method="post">
    <input name="username"><input name="password">
    <input type="submit" value="go">
  </form>
</body></html>
"""


def _pages(mapping):
    def fetch(url):
        for key, body in mapping.items():
            if url.split("?")[0].rstrip("/") == key.rstrip("/"):
                return {"status": 200, "headers": {}, "body": body, "url": url}
        return None

    return fetch


def test_normalize_base_accepts_bare_host():
    assert normalize_base("localhost:8801") == "http://localhost:8801"
    assert normalize_base("http://x/") == "http://x"


def test_unreachable_target_yields_no_endpoints():
    result = discover_surface("http://localhost:9", fetcher=lambda url: None)
    assert result["reachable"] is False
    assert result["endpoints"] == []


def test_form_params_are_discovered():
    result = discover_surface("http://t", fetcher=_pages({"http://t/": _INDEX}))
    login = next(e for e in result["endpoints"] if e["url"].endswith("/login"))
    assert login["method"] == "POST"
    assert set(login["params"]) == {"username", "password"}
    assert "submit" not in login["params"]


def test_query_params_on_links_are_discovered():
    result = discover_surface("http://t", fetcher=_pages({"http://t/": _INDEX}))
    search = next(e for e in result["endpoints"] if e["url"].endswith("/search"))
    assert search["params"] == ["q"]


def test_offsite_links_are_not_followed():
    result = discover_surface("http://t", fetcher=_pages({"http://t/": _INDEX}))
    assert all("evil.example.com" not in e["url"] for e in result["endpoints"])


def test_self_advertised_hint_resolves_to_its_own_route():
    """A hint read on the index describes another route; the path must survive."""
    body = '{"service": "cmdi_ping", "hint": "GET /ping?host="}'
    result = discover_surface("http://t", fetcher=_pages({"http://t/": body}))
    ping = next(e for e in result["endpoints"] if e["url"].endswith("/ping"))
    assert ping["method"] == "GET"
    assert ping["params"] == ["host"]


def test_post_style_hint_is_parsed():
    body = '{"service": "sqli_login", "hint": "POST /login username,password"}'
    result = discover_surface("http://t", fetcher=_pages({"http://t/": body}))
    login = next(e for e in result["endpoints"] if e["url"].endswith("/login"))
    assert login["method"] == "POST"
    assert set(login["params"]) == {"username", "password"}


def test_malformed_html_does_not_abort():
    result = discover_surface("http://t", fetcher=_pages({"http://t/": "<form><input name=a>"}))
    assert result["reachable"] is True


def test_page_budget_is_respected():
    calls = []

    def fetch(url):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": _INDEX, "url": url}

    discover_surface("http://t", fetcher=fetch, depth=5, max_pages=3)
    assert len(calls) <= 3


def test_recon_agent_skips_web_surface_by_default():
    """The flag defaults off: an existing scan gains no new HTTP traffic."""
    from unittest.mock import patch

    from cyberai.core.config import CyberAIConfig

    assert CyberAIConfig().use_web_recon is False

    with patch("cyberai.agents.recon.agent.discover_surface") as spy:
        cfg = CyberAIConfig()
        assert getattr(cfg, "use_web_recon", False) is False
        spy.assert_not_called()


def test_api_discovery_is_off_by_default():
    asked = []

    def fetch(url):
        asked.append(url)
        return {"status": 200, "headers": {}, "body": "<html></html>", "url": url}

    result = discover_surface("http://t", fetcher=fetch)
    assert not any("openapi" in url for url in asked)
    assert result["routes"] == [] and result["spec_url"] is None


def test_api_discovery_merges_spec_endpoints_into_the_surface():
    spec = json.dumps(
        {"paths": {"/ping": {"get": {"parameters": [{"name": "host", "in": "query"}]}}}}
    )
    shell = '<html><body><div id="app"></div></body></html>'

    def fetch(url):
        if url.rstrip("/") == "http://t":
            return {"status": 200, "headers": {}, "body": shell, "url": url}
        if url == "http://t/openapi.json":
            return {"status": 200, "headers": {}, "body": spec, "url": url}
        return None

    result = discover_surface("http://t", fetcher=fetch, api_discovery=True)
    assert result["spec_url"] == "http://t/openapi.json"
    assert [(e["url"], e["params"], e["source"]) for e in result["endpoints"]] == [
        ("http://t/ping", ["host"], "openapi")
    ]


def test_api_discovery_makes_a_spec_only_target_reachable():
    spec = json.dumps(
        {"paths": {"/ping": {"get": {"parameters": [{"name": "host", "in": "query"}]}}}}
    )

    def fetch(url):
        if url == "http://t/openapi.json":
            return {"status": 200, "headers": {}, "body": spec, "url": url}
        return None

    result = discover_surface("http://t", fetcher=fetch, api_discovery=True)
    assert result["reachable"] is True
    assert result["pages_fetched"] == 0


def test_api_discovery_config_flag_defaults_off():
    from cyberai.core.config import CyberAIConfig

    assert CyberAIConfig().use_api_discovery is False
