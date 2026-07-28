"""Tests for API attack-surface discovery."""

from __future__ import annotations

import json

from cyberai.agents.recon.api_surface import (
    discover_api_surface,
    fetch_js_routes,
    fetch_openapi,
    parse_openapi,
    probe_well_known,
    routes_from_javascript,
    script_urls,
)

_OAS3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "http://t/api"}],
    "paths": {
        "/search": {
            "get": {"parameters": [{"name": "q", "in": "query"}, {"name": "auth", "in": "header"}]}
        },
        "/switch_path": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/PathReq"}}
                    }
                }
            }
        },
        "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
    },
    "components": {
        "schemas": {"PathReq": {"type": "object", "properties": {"path": {"type": "string"}}}}
    },
}

_SWAGGER2 = {
    "swagger": "2.0",
    "basePath": "/v1",
    "paths": {
        "/login": {
            "post": {
                "parameters": [
                    {"name": "user", "in": "formData"},
                    {"name": "body", "in": "body", "schema": {"properties": {"token": {}}}},
                ]
            }
        }
    },
}


def _pages(mapping):
    def fetch(url):
        if url in mapping:
            body = mapping[url]
            return {"status": 200, "headers": {}, "body": body, "url": url}
        return None

    return fetch


def test_query_parameters_are_read_from_spec():
    eps = parse_openapi(_OAS3, "http://t")
    search = [e for e in eps if e["url"].endswith("/search")]
    assert len(search) == 1
    assert search[0]["method"] == "GET"
    assert search[0]["params"] == ["q"]
    assert search[0]["source"] == "openapi"


def test_server_url_contributes_only_its_path():
    eps = parse_openapi(_OAS3, "http://t")
    assert all(e["url"].startswith("http://t/api/") for e in eps)


def test_body_schema_ref_is_resolved_into_parameters():
    eps = parse_openapi(_OAS3, "http://t")
    switch = [e for e in eps if e["url"].endswith("/switch_path")][0]
    assert switch["method"] == "POST"
    assert switch["params"] == ["path"]


def test_templated_paths_are_skipped():
    eps = parse_openapi(_OAS3, "http://t")
    assert not any("{" in e["url"] for e in eps)
    assert not any(e["url"].endswith("/users") for e in eps)


def test_swagger2_base_path_and_body_parameter():
    eps = parse_openapi(_SWAGGER2, "http://t")
    assert len(eps) == 1
    assert eps[0]["url"] == "http://t/v1/login"
    assert eps[0]["params"] == ["user", "token"]


def test_path_level_parameters_are_merged_into_operations():
    spec = {
        "paths": {
            "/x": {
                "parameters": [{"name": "shared", "in": "query"}],
                "get": {"parameters": [{"name": "own", "in": "query"}]},
                "summary": "not an operation",
            }
        }
    }
    eps = parse_openapi(spec, "http://t")
    assert len(eps) == 1
    assert eps[0]["params"] == ["shared", "own"]


def test_malformed_spec_yields_no_endpoints():
    assert parse_openapi(None, "http://t") == []
    assert parse_openapi({"paths": "nope"}, "http://t") == []
    assert parse_openapi({}, "http://t") == []


def test_fetch_openapi_finds_first_published_spec():
    result = fetch_openapi("http://t", _pages({"http://t/swagger.json": json.dumps(_SWAGGER2)}))
    assert result["spec_url"] == "http://t/swagger.json"
    assert result["endpoints"][0]["params"] == ["user", "token"]


def test_fetch_openapi_ignores_html_and_errors():
    fetch = _pages({"http://t/openapi.json": "<html>not a spec</html>"})
    assert fetch_openapi("http://t", fetch) == {"spec_url": None, "endpoints": []}


def test_fetch_openapi_ignores_error_status():
    def fetch(url):
        return {"status": 404, "headers": {}, "body": json.dumps(_SWAGGER2), "url": url}

    assert fetch_openapi("http://t", fetch)["spec_url"] is None


def test_no_spec_anywhere_is_not_a_guess():
    assert fetch_openapi("http://t", lambda url: None) == {"spec_url": None, "endpoints": []}


_BUNDLE = """
axios.post("/switch_personal_path", {path: userPath});
fetch("/api/items?limit=10&offset=0");
fetch("/api/login", {method:"POST", headers:{}, body: JSON.stringify({username:u, password:p})});
r.get("/health");
const logo = "/static/logo.png"; import "/assets/index-4f3a.js"; const t = `/tpl/${id}`;
"""

_SHELL = '<html><body><div id="app"></div><script src="/assets/app.js"></script></body></html>'


def _routes(text):
    return {(r["path"], r["method"]): r["params"] for r in routes_from_javascript(text)}


def test_call_argument_object_yields_body_field():
    assert _routes(_BUNDLE)[("/switch_personal_path", "POST")] == ["path"]


def test_query_string_on_literal_becomes_parameters():
    assert _routes(_BUNDLE)[("/api/items", "GET")] == ["limit", "offset"]


def test_options_object_drops_transport_keys_but_keeps_payload_fields():
    assert _routes(_BUNDLE)[("/api/login", "POST")] == ["username", "password"]


def test_adjacent_calls_do_not_leak_parameters():
    text = 'n.post("/a",{title:t});fetch("/b",{method:"POST",body:JSON.stringify({secret:s})});'
    found = _routes(text)
    assert found[("/a", "POST")] == ["title"]
    assert found[("/b", "POST")] == ["secret"]


def test_assets_and_template_literals_are_not_routes():
    paths = {path for path, _ in _routes(_BUNDLE)}
    assert paths == {"/switch_personal_path", "/api/items", "/api/login", "/health"}


def test_route_without_parameters_is_still_reported():
    assert _routes(_BUNDLE)[("/health", "GET")] == []


def test_max_routes_is_capped():
    text = ";".join(f'fetch("/r{i}")' for i in range(60))
    assert len(routes_from_javascript(text, max_routes=5)) == 5


def test_script_urls_are_same_origin_and_ordered():
    html = '<script src="/a.js"></script><script src="https://cdn.x/b.js"></script>'
    html += '<script src="/a.js"></script><script src="/c.js"></script>'
    assert script_urls(html, "http://t/", "http://t") == ["http://t/a.js", "http://t/c.js"]


def test_script_urls_respect_limit():
    html = "".join(f'<script src="/{i}.js"></script>' for i in range(10))
    assert len(script_urls(html, "http://t/", "http://t", limit=3)) == 3


def test_fetch_js_routes_absolutises_paths_and_records_bundles():
    result = fetch_js_routes("http://t", _pages({"http://t/assets/app.js": _BUNDLE}), _SHELL)
    assert result["scripts"] == ["http://t/assets/app.js"]
    urls = {e["url"] for e in result["endpoints"]}
    assert "http://t/switch_personal_path" in urls
    assert all(e["source"] == "js-route" for e in result["endpoints"])


def test_fetch_js_routes_without_bundles_returns_nothing():
    result = fetch_js_routes("http://t", lambda url: None, "<html><body></body></html>")
    assert result == {"scripts": [], "endpoints": []}


def _statuses(mapping, default=404):
    def fetch(url):
        return {"status": mapping.get(url, default), "headers": {}, "body": "", "url": url}

    return fetch


def test_probe_reports_reachable_and_guarded_paths_only():
    fetch = _statuses({"http://t/api": 200, "http://t/admin": 403, "http://t/graphql": 500})
    urls = [e["url"] for e in probe_well_known("http://t", fetch)]
    assert urls == ["http://t/api", "http://t/admin"]
    assert all(
        e["params"] == [] and e["source"] == "well-known"
        for e in probe_well_known("http://t", fetch)
    )


def test_probe_treats_dead_target_as_absence():
    assert probe_well_known("http://t", lambda url: None) == []


def test_spec_endpoints_win_and_bare_routes_are_separated():
    pages = {
        "http://t/openapi.json": json.dumps(_SWAGGER2),
        "http://t/assets/app.js": _BUNDLE,
    }
    result = discover_api_surface("http://t", _pages(pages), html=_SHELL)
    assert result["spec_url"] == "http://t/openapi.json"
    assert result["scripts"] == ["http://t/assets/app.js"]
    injectable = {(e["url"], e["method"]) for e in result["endpoints"]}
    assert ("http://t/v1/login", "POST") in injectable
    assert ("http://t/switch_personal_path", "POST") in injectable
    assert [r["url"] for r in result["routes"]] == ["http://t/health"]


def test_conventions_are_probed_only_when_nothing_injectable_was_found():
    probed = []

    def fetch(url):
        probed.append(url)
        return None

    discover_api_surface("http://t", fetch, html="")
    assert "http://t/api" in probed


def test_conventions_are_skipped_once_a_parameter_is_known():
    pages = _pages({"http://t/assets/app.js": _BUNDLE})
    seen = []

    def fetch(url):
        seen.append(url)
        return pages(url)

    discover_api_surface("http://t", fetch, html=_SHELL)
    assert not any(url.endswith("/graphql") for url in seen)


def test_same_route_from_two_sources_merges_parameters():
    spec = {
        "paths": {"/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}}},
    }
    bundle = 'fetch("/search?page=2");'
    pages = _pages({"http://t/openapi.json": json.dumps(spec), "http://t/assets/app.js": bundle})
    result = discover_api_surface("http://t", pages, html=_SHELL)
    assert len(result["endpoints"]) == 1
    assert result["endpoints"][0]["params"] == ["q", "page"]


def test_empty_target_yields_empty_surface():
    result = discover_api_surface("http://t", lambda url: None, html="", probe_conventions=False)
    assert result == {"endpoints": [], "routes": [], "spec_url": None, "scripts": []}


# A GET that requires a JSON body: not hypothetical -- a real FastAPI target in
# the CVE-Bench suite declares its vulnerable route exactly this way, and
# sending the field as a query parameter only ever earns a validation error.
_GET_WITH_BODY = {
    "openapi": "3.0.0",
    "paths": {
        "/switch_personal_path": {
            "get": {
                "parameters": [{"name": "confirm", "in": "query"}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/PathReq"}}
                    },
                },
            }
        }
    },
    "components": {"schemas": {"PathReq": {"properties": {"path": {"type": "string"}}}}},
}


def test_body_fields_are_marked_separately_from_query_fields():
    endpoint = parse_openapi(_GET_WITH_BODY, "http://t")[0]
    assert endpoint["method"] == "GET"
    assert endpoint["params"] == ["confirm", "path"]
    assert endpoint["body_params"] == ["path"]


def test_query_only_operation_has_no_body_params():
    endpoint = [e for e in parse_openapi(_OAS3, "http://t") if e["url"].endswith("/search")][0]
    assert endpoint["body_params"] == []


def test_merged_surface_keeps_the_body_marking():
    pages = _pages({"http://t/openapi.json": json.dumps(_GET_WITH_BODY)})
    result = discover_api_surface("http://t", pages)
    assert result["endpoints"][0]["body_params"] == ["path"]
