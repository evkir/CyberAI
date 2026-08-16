"""Tests for API attack-surface discovery."""

from __future__ import annotations

import json

from cyberai.agents.recon.api_surface import (
    discover_api_surface,
    fetch_js_routes,
    fetch_openapi,
    parse_openapi,
    parse_wp_rest,
    probe_route_params,
    probe_well_known,
    _merge_route,
    routes_from_concatenated_base,
    routes_from_javascript,
    script_urls,
    spec_url_from_link,
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


def test_templated_path_keeps_the_template_and_names_its_parameter():
    eps = parse_openapi(_OAS3, "http://t")
    users = [e for e in eps if "{id}" in e["url"]]
    assert len(users) == 1
    assert users[0]["url"] == "http://t/api/users/{id}"
    assert users[0]["path_params"] == ["id"]
    assert users[0]["params"] == ["id"]
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


_WP = {
    "routes": {
        "/wp/v2/posts": {
            "endpoints": [
                {"methods": ["GET"], "args": {"search": {}, "context": {}}},
                {"methods": ["POST"], "args": {"title": {}}},
            ]
        },
        "/wp/v2/posts/(?P<parent>[\\d]+)/revisions/(?P<id>[\\d]+)": {
            "endpoints": [{"methods": ["GET", "DELETE"], "args": {"force": {}}}]
        },
        "/batch/v1": {
            "endpoints": [
                {
                    "methods": ["POST"],
                    "args": {
                        "requests": {
                            "type": "array",
                            "items": {"properties": {"path": {}, "body": {}}},
                        }
                    },
                }
            ]
        },
    }
}


def test_wp_route_regex_becomes_the_template_form_used_everywhere_else():
    urls = {e["url"] for e in parse_wp_rest(_WP, "http://t/wp-json")}
    assert "http://t/wp-json/wp/v2/posts/{parent}/revisions/{id}" in urls


def test_wp_path_groups_are_named_as_path_params():
    revisions = [e for e in parse_wp_rest(_WP, "http://t/wp-json") if "{id}" in e["url"]]
    assert revisions, "the templated route produced no endpoint"
    assert all(e["path_params"] == ["parent", "id"] for e in revisions)
    assert all({"parent", "id"} <= set(e["params"]) for e in revisions)


def test_each_operation_keeps_its_own_arguments():
    posts = {
        e["method"]: e["params"]
        for e in parse_wp_rest(_WP, "http://t/wp-json")
        if e["url"] == "http://t/wp-json/wp/v2/posts"
    }
    assert posts["GET"] == ["search", "context"]
    assert posts["POST"] == ["title"], "a POST must not inherit the names a GET reads"


def test_nested_argument_properties_are_not_route_parameters():
    batch = [e for e in parse_wp_rest(_WP, "http://t/wp-json") if e["url"].endswith("/batch/v1")]
    assert batch and batch[0]["params"] == ["requests"]


def test_a_link_entry_without_a_bracket_or_a_rel_is_skipped():
    """Both halves of an entry are required; neither is assumed present."""
    assert spec_url_from_link({"link": "no-brackets-here; rel=preload"}, "http://t") is None
    assert spec_url_from_link({"link": "</x>; nofollow"}, "http://t") is None


def test_a_document_that_is_not_a_wp_index_yields_nothing():
    assert parse_wp_rest("not a dict", "http://t") == []
    assert parse_wp_rest({"paths": {}}, "http://t") == []


def test_a_wp_index_full_of_wrong_types_is_read_for_what_it_does_declare():
    """A document is untrusted input: every level may hold something else."""
    spec = {
        "routes": {
            7: {"endpoints": []},
            "/bad-item": "not a dict",
            "/bad-endpoints": {"endpoints": "not a list"},
            "/bad-operation": {"endpoints": ["not a dict"]},
            "/head-only": {"endpoints": [{"methods": ["HEAD", "OPTIONS"], "args": {"a": {}}}]},
            "/good": {"endpoints": [{"methods": ["GET"], "args": {"q": {}}}]},
        }
    }
    endpoints = parse_wp_rest(spec, "http://t/wp-json")
    assert [e["url"] for e in endpoints] == ["http://t/wp-json/good"], (
        "only the operations this module can act on survive"
    )


def test_a_body_that_is_not_a_json_object_is_not_a_spec():
    def fetch(url):
        if url == "http://t":
            return {"status": 200, "headers": {}, "body": ""}
        if url == "http://t/openapi.json":
            return {"status": 200, "headers": {}, "body": "   "}
        if url == "http://t/swagger.json":
            return {"status": 200, "headers": {}, "body": "[1, 2, 3]"}
        if url == "http://t/api/openapi.json":
            return {"status": 200, "headers": {}, "body": '{"info": {}}'}
        return {"status": 404, "headers": {}, "body": ""}

    assert fetch_openapi("http://t", fetch)["spec_url"] is None


def test_the_advertised_root_is_read_before_the_conventional_guesses():
    """A Link header is one request against eight, and the eight are 404 here."""
    wp = json.dumps(_WP)
    seen: list[str] = []

    def fetch(url):
        seen.append(url)
        if url == "http://t":
            return {
                "status": 200,
                "headers": {"link": '<http://alias/wp-json/>; rel="https://api.w.org/"'},
                "body": "",
            }
        if url == "http://t/wp-json":
            return {"status": 200, "headers": {}, "body": wp}
        return {"status": 404, "headers": {}, "body": ""}

    found = fetch_openapi("http://t", fetch)
    assert found["spec_url"] == "http://t/wp-json"
    assert found["endpoints"], "the advertised document produced no endpoints"
    assert not [u for u in seen if u.endswith("/openapi.json")], (
        "a target that told us where its spec is must not be guessed at"
    )


def test_a_link_to_something_that_is_not_a_spec_does_not_stop_the_probe():
    spec = json.dumps({"paths": {"/x": {"get": {}}}})

    def fetch(url):
        if url == "http://t":
            return {
                "status": 200,
                "headers": {"link": '<http://t/api>; rel="describedby"'},
                "body": "",
            }
        if url == "http://t/api":
            return {"status": 200, "headers": {}, "body": "<html>not a spec</html>"}
        if url == "http://t/openapi.json":
            return {"status": 200, "headers": {}, "body": spec}
        return {"status": 404, "headers": {}, "body": ""}

    assert fetch_openapi("http://t", fetch)["spec_url"] == "http://t/openapi.json"


def test_a_link_header_names_the_api_root():
    headers = {"link": '<http://target:9090/wp-json/>; rel="https://api.w.org/"'}
    assert spec_url_from_link(headers, "http://127.0.0.1:9090") == ("http://127.0.0.1:9090/wp-json")


def test_the_host_in_a_link_header_is_not_followed():
    """The document names its compose alias; the scan stays on the target we were given."""
    headers = {"link": '<http://evil.example/wp-json/>; rel="https://api.w.org/"'}
    assert spec_url_from_link(headers, "http://127.0.0.1:9090") == ("http://127.0.0.1:9090/wp-json")


def test_a_link_that_is_not_an_api_relation_says_nothing():
    headers = {"link": "</style.css>; rel=preload"}
    assert spec_url_from_link(headers, "http://127.0.0.1:9090") is None


def test_the_api_relation_is_found_among_several_entries():
    headers = {
        "link": '</s/x>; rel="shortlink", <http://target/wp-json/>; rel="https://api.w.org/"'
    }
    assert spec_url_from_link(headers, "http://127.0.0.1:9090") == ("http://127.0.0.1:9090/wp-json")


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


def test_angular_delivery_options_are_not_parameters():
    """An Angular service writes no `method:`, so its options bag needs naming.

    Sending `reportProgress` at a server spends the request budget on a field
    the bundle never meant for it, and puts an invented name in the report.
    """
    text = (
        'host=b+"/rest/chat";'
        "n.post(this.host,{messages:e},"
        '{responseType:"text",observe:"events",reportProgress:!0});'
    )
    assert _concat(text)[("/rest/chat", "POST")] == ["messages"]


def test_a_lone_params_object_is_the_query_bag():
    text = 'n.get("/api/Products/",{params:e});'
    assert _routes(text)[("/api/Products/", "GET")] == []


def test_params_beside_a_real_field_is_still_dropped_only_as_transport():
    """`params` next to other fields stays readable as what the object is."""
    text = 'n.post("/a",{params:p,title:t});'
    assert _routes(text)[("/a", "POST")] == ["params", "title"]


def test_adjacent_calls_do_not_leak_parameters():
    text = 'n.post("/a",{title:t});fetch("/b",{method:"POST",body:JSON.stringify({secret:s})});'
    found = _routes(text)
    assert found[("/a", "POST")] == ["title"]
    assert found[("/b", "POST")] == ["secret"]


def test_assets_are_not_routes():
    """A build references its own files by path; requesting them proves nothing."""
    paths = {path for path, _ in _routes(_BUNDLE)}
    assert paths == {
        "/switch_personal_path",
        "/api/items",
        "/api/login",
        "/health",
        "/tpl/{id}",
    }
    assert not any(p.startswith("/static/") or p.startswith("/assets/") for p in paths)


def test_template_literal_becomes_a_path_parameter():
    """An interpolated segment is a slot to inject into, not noise to discard.

    Dropping these hid every route a bundled SPA builds from its own base URL,
    which on a real target is most of the API.
    """
    routes = _routes(_BUNDLE)
    assert ("/tpl/{id}", "GET") in routes


def test_route_without_parameters_is_still_reported():
    assert _routes(_BUNDLE)[("/health", "GET")] == []


_CONCAT_BUNDLE = """
class A{host=this.hostServer+"/rest/user";erase(e){return this.http.post(this.host+"/erasure-request",e)}}
class B{host=this.hostServer+"/api/Hints";getAll(){return this.http.get(this.host+"/")}}
class C{host=this.hostServer+"/rest/wallet/balance";get(){return this.http.get(this.host)}put(e){return this.http.put(this.host,{amount:e})}}
"""


def _concat(text):
    return {(r["path"], r["method"]): r["params"] for r in routes_from_concatenated_base(text)}


def test_tail_joins_the_base_declared_for_that_field():
    """The half-paths are both in the bundle; neither is a route on its own."""
    assert ("/rest/user/erasure-request", "POST") in _concat(_CONCAT_BUNDLE)


def test_a_tail_does_not_join_a_base_from_another_class():
    """Pairing every base with every tail invents paths no service calls."""
    assert set(_concat(_CONCAT_BUNDLE)) == {
        ("/rest/user/erasure-request", "POST"),
        ("/api/Hints", "GET"),
        ("/rest/wallet/balance", "GET"),
        ("/rest/wallet/balance", "PUT"),
    }


def test_base_called_with_no_tail_is_itself_a_route():
    found = _concat(_CONCAT_BUNDLE)
    assert ("/api/Hints", "GET") in found
    assert ("/rest/wallet/balance", "GET") in found


def test_verbs_on_one_path_stay_apart():
    found = _concat(_CONCAT_BUNDLE)
    assert ("/rest/wallet/balance", "PUT") in found
    assert found[("/rest/wallet/balance", "PUT")] == ["amount"]
    assert found[("/rest/wallet/balance", "GET")] == []


def test_bundle_without_a_base_declaration_yields_nothing():
    assert routes_from_concatenated_base('n.post("/a",{t:1});') == []


def test_a_call_on_a_field_no_declaration_names_is_left_alone():
    """A bundle declares one base and calls through another field.

    Not the same as a bundle with no declarations at all: here the reader has
    a table and still has to decline, because pairing the tail with whatever
    base happens to be nearby invents a path the service never calls.
    """
    text = 'class A{host=this.h+"/rest/user";go(){return this.http.get(this.other+"/x")}}'
    assert routes_from_concatenated_base(text) == []
    reached = 'class A{host=this.h+"/rest/user";go(){return this.http.get(this.host+"/x")}}'
    assert [r["path"] for r in routes_from_concatenated_base(reached)] == ["/rest/user/x"]


def test_a_base_and_tail_that_land_on_an_asset_are_not_a_route():
    """Halves that each look routable can still join into a file."""
    text = 'class A{host=this.h+"/assets";go(){return this.http.get(this.host+"/app.js")}}'
    assert routes_from_concatenated_base(text) == []


def test_one_path_named_by_both_readers_keeps_the_names_each_saw():
    """The merge exists because a path arrives twice with different fields.

    Whichever reader lands second must add to the names rather than replace
    them: the literal reader sees the call site, the concatenating reader sees
    another, and dropping either loses parameters that are really there.
    """
    text = (
        'class A{host=this.h+"/u";go(){return this.http.post(this.host+"/x",{q:1})}}'
        'n.post("/u/x",{r:2});'
    )
    merged: dict = {}
    for route in routes_from_javascript(text) + routes_from_concatenated_base(text):
        _merge_route(merged, route)

    # Both readers reach this one key, each with a name the other missed. The
    # other keys in the table are the halves the literal reader also sees on
    # their own, and they are not what this pins.
    from_literal = [r for r in routes_from_javascript(text) if r["path"] == "/u/x"]
    from_concat = [r for r in routes_from_concatenated_base(text) if r["path"] == "/u/x"]
    assert len(from_literal) == 1 and len(from_concat) == 1
    assert from_literal[0]["params"] != from_concat[0]["params"]

    assert sorted(merged[("/u/x", "POST")]["params"]) == ["q", "r"]


def test_concatenated_routes_are_capped():
    text = ";".join(f'x=b+"/base{i}";n.get(this.x+"/t")' for i in range(60))
    assert len(routes_from_concatenated_base(text, max_routes=5)) == 5


_TWO_FORM_BUNDLE = (
    'class S{host=this.hostServer+"/rest/wallet/balance";'
    "get(){return this.http.get(this.host)}"
    "put(e){return this.http.put(this.host,{amount:e})}}"
    'n.get("/rest/wallet/balance?currency=eur");'
)


def _js(text):
    result = fetch_js_routes("http://t", lambda url: {"body": text}, _SHELL)
    return {(e["url"], e["method"]): e for e in result["endpoints"]}


def test_both_readers_feed_one_table():
    """A bundle names its API two ways at once; the same path must not double."""
    found = _js(_TWO_FORM_BUNDLE)
    assert len([k for k in found if k[0].endswith("/rest/wallet/balance")]) == 2


def test_a_path_found_twice_keeps_names_from_both_readers():
    """Whichever reader ran second must not drop what only the first saw."""
    found = _js(_TWO_FORM_BUNDLE)
    assert found[("http://t/rest/wallet/balance", "GET")]["params"] == ["currency"]


def test_a_verb_only_the_concatenating_reader_sees_reaches_the_surface():
    found = _js(_TWO_FORM_BUNDLE)
    assert ("http://t/rest/wallet/balance", "PUT") in found
    assert found[("http://t/rest/wallet/balance", "PUT")]["params"] == ["amount"]


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


def test_placeholder_absent_from_the_document_is_still_a_parameter():
    spec = {"paths": {"/items/{item_id}/tags": {"get": {}}}}
    endpoint = parse_openapi(spec, "http://t")[0]
    assert endpoint["path_params"] == ["item_id"]
    assert endpoint["params"] == ["item_id"]


def test_repeated_placeholder_is_named_once():
    spec = {"paths": {"/a/{k}/b/{k}": {"get": {}}}}
    assert parse_openapi(spec, "http://t")[0]["path_params"] == ["k"]


def test_untemplated_path_reports_no_path_parameters():
    spec = {"paths": {"/plain": {"get": {"parameters": [{"name": "q", "in": "query"}]}}}}
    endpoint = parse_openapi(spec, "http://t")[0]
    assert endpoint["path_params"] == []
    assert endpoint["params"] == ["q"]


def test_path_parameter_precedes_declared_parameters():
    spec = {
        "paths": {
            "/u/{uid}": {
                "parameters": [{"name": "shared", "in": "query"}],
                "get": {"parameters": [{"name": "own", "in": "query"}]},
            }
        }
    }
    assert parse_openapi(spec, "http://t")[0]["params"] == ["uid", "shared", "own"]


def _responses(mapping):
    """Fake fetcher: url -> (status, body). An unmapped url answers 404."""

    def fetch(url):
        status, body = mapping.get(url, (404, ""))
        return {"status": status, "headers": {}, "body": body, "url": url}

    return fetch


def _route(url, method="GET"):
    return {"url": url, "method": method, "params": [], "source": "js"}


def test_a_route_that_reads_a_synthesized_name_becomes_an_endpoint():
    fetch = _responses(
        {"http://t/api/Items": (200, "all"), "http://t/api/Items?q=1": (200, "filtered")}
    )
    promoted = probe_route_params([_route("http://t/api/Items")], fetch)
    assert [(e["url"], e["params"], e["source"]) for e in promoted] == [
        ("http://t/api/Items", ["q"], "probed")
    ]


def test_a_route_that_ignores_every_name_stays_a_route():
    same = (200, "all")
    fetch = _responses(
        {
            "http://t/api/Items": same,
            "http://t/api/Items?q=1": same,
            "http://t/api/Items?id=1": same,
            "http://t/api/Items?page=1": same,
            "http://t/api/Items?name=1": same,
        }
    )
    assert probe_route_params([_route("http://t/api/Items")], fetch) == []


def test_a_parameter_that_breaks_the_route_counts_as_read():
    fetch = _responses(
        {"http://t/api/Items": (200, "all"), "http://t/api/Items?q=1": (500, "SQLITE_ERROR")}
    )
    assert [e["params"] for e in probe_route_params([_route("http://t/api/Items")], fetch)] == [
        ["q"]
    ]


def test_a_route_that_answers_itself_differently_is_not_measurable():
    calls = []

    def fetch(url):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": "nonce-%d" % len(calls), "url": url}

    assert probe_route_params([_route("http://t/rest/captcha")], fetch) == []
    assert len(calls) == 3


def test_a_route_that_already_carries_a_query_gets_an_ampersand():
    fetch = _responses(
        {"http://t/s?lang=en": (200, "all"), "http://t/s?lang=en&q=1": (200, "filtered")}
    )
    assert [e["params"] for e in probe_route_params([_route("http://t/s?lang=en")], fetch)] == [
        ["q"]
    ]


def test_a_route_behind_a_refusal_costs_one_request_and_no_more():
    calls = []

    def fetch(url):
        calls.append(url)
        return {"status": 401, "headers": {}, "body": "denied", "url": url}

    assert probe_route_params([_route("http://t/api/Users")], fetch) == []
    assert calls == ["http://t/api/Users"]


def test_placeholder_and_state_changing_routes_are_left_alone():
    calls = []

    def fetch(url):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": "x", "url": url}

    routes = [
        _route("http://t/api/Items/{id}"),
        _route("http://t/api/Items", method="POST"),
        _route(""),
    ]
    assert probe_route_params(routes, fetch) == []
    assert calls == []


def test_a_dead_target_promotes_nothing():
    assert probe_route_params([_route("http://t/a")], lambda url: None) == []


def test_a_probe_that_gets_no_answer_is_not_a_reaction():
    def fetch(url):
        if url == "http://t/a":
            return {"status": 200, "headers": {}, "body": "all", "url": url}
        return None

    assert probe_route_params([_route("http://t/a")], fetch) == []


def test_probing_stops_at_the_request_budget():
    calls = []

    def fetch(url):
        calls.append(url)
        return {"status": 200, "headers": {}, "body": "same", "url": url}

    routes = [_route("http://t/a%d" % i) for i in range(10)]
    probe_route_params(routes, fetch, max_probes=6)
    assert len(calls) == 6


_PROBE_SHELL = '<html><body><script src="/main.js"></script></body></html>'


def test_probing_moves_a_reading_route_out_of_routes():
    pages = {
        "http://t/main.js": (200, 'fetch("/api/Items"); fetch("/api/Logs");'),
        "http://t/api/Items": (200, "all"),
        "http://t/api/Items?q=1": (200, "filtered"),
        "http://t/api/Logs": (200, "log"),
        "http://t/api/Logs?q=1": (200, "log"),
        "http://t/api/Logs?id=1": (200, "log"),
        "http://t/api/Logs?page=1": (200, "log"),
        "http://t/api/Logs?name=1": (200, "log"),
    }
    result = discover_api_surface(
        "http://t", _responses(pages), html=_PROBE_SHELL, probe_routes=True
    )
    assert [(e["url"], e["params"]) for e in result["endpoints"]] == [("http://t/api/Items", ["q"])]
    assert [r["url"] for r in result["routes"]] == ["http://t/api/Logs"]


def test_routes_are_left_alone_unless_probing_is_asked_for():
    pages = {
        "http://t/main.js": (200, 'fetch("/api/Items");'),
        "http://t/api/Items": (200, "all"),
        "http://t/api/Items?q=1": (200, "filtered"),
    }
    result = discover_api_surface("http://t", _responses(pages), html=_PROBE_SHELL)
    assert result["endpoints"] == []
    assert [r["url"] for r in result["routes"]] == ["http://t/api/Items"]


def test_a_reply_missing_its_body_is_not_an_answer():
    """A dict without a usable body is no more comparable than no reply."""

    def fetch(url):
        if "?" in url:
            return {"status": 200, "headers": {}, "url": url}
        return {"status": 200, "headers": {}, "body": "all", "url": url}

    assert probe_route_params([_route("http://t/a")], fetch) == []


_ENDPOINT_KEYS = {"url", "method", "params", "body_params", "path_params", "source"}


def test_every_endpoint_carries_the_whole_shape_whichever_path_built_it():
    """Three call sites assembled this record by hand and each carried a
    different subset, so a consumer could not tell a field dropped at the
    source from a field with no value. path_params was lost across this
    boundary three times and source once; a single constructor is only worth
    anything if something fails when a site stops using it.
    """
    pages = {
        "http://t/openapi.json": json.dumps(_SWAGGER2),
        "http://t/assets/app.js": _BUNDLE,
    }
    result = discover_api_surface("http://t", _pages(pages), html=_SHELL)
    records = result["endpoints"] + result["routes"]
    assert records
    for record in records:
        assert set(record.keys()) == _ENDPOINT_KEYS, record


def test_each_endpoint_says_which_source_produced_it():
    """The keys being present is not the same as the value arriving: a
    constructor with defaults answers an omitted argument with a blank.
    """
    pages = {
        "http://t/openapi.json": json.dumps(_SWAGGER2),
        "http://t/assets/app.js": _BUNDLE,
    }
    result = discover_api_surface("http://t", _pages(pages), html=_SHELL)
    by_url = {e["url"]: e["source"] for e in result["endpoints"] + result["routes"]}
    assert by_url["http://t/v1/login"] == "openapi"
    assert by_url["http://t/switch_personal_path"] == "js-route"


def test_a_templated_route_keeps_its_path_parameter_through_the_bundle_path():
    """The spec path asserts this and the bundle path never did.

    Dropping path_params here left every test green, which is how the field
    went missing three times. The name is what the exploit side substitutes to
    make the route resolve at all, so losing it does not weaken a request --
    it stops the request from landing.
    """
    result = discover_api_surface(
        "http://t", _pages({"http://t/assets/app.js": _BUNDLE}), html=_SHELL
    )
    by_url = {e["url"]: e for e in result["endpoints"] + result["routes"]}
    assert by_url["http://t/tpl/{id}"]["path_params"] == ["id"]


def test_a_well_known_path_is_shaped_like_every_other_endpoint():
    def fetch(url):
        if url == "http://t/api":
            return {"status": 200, "headers": {}, "body": "ok", "url": url}
        return None

    found = probe_well_known("http://t", fetch)
    assert found
    for record in found:
        assert set(record.keys()) == _ENDPOINT_KEYS, record
        assert record["source"] == "well-known"
