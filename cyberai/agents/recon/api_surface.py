"""API attack-surface discovery for targets whose HTML carries nothing to follow.

A single-page application serves an empty shell: no anchors, no forms, nothing
an HTML crawler can act on. Its real surface is published elsewhere -- in an
OpenAPI document, in the route table compiled into a JS bundle, or behind a
handful of conventional paths. This module reads those sources and returns the
endpoint shape `web_surface` already produces, so exploitation needs no change.

Nothing here is asserted without the target's own answer. A route or a
parameter name may be synthesized, but a synthesized name enters the endpoint
list only once the target answered it differently from its own baseline: the
guess is what we send, never what we report. An operation whose path still
holds a template placeholder is skipped rather than filled with a guessed
value.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urljoin, urlparse

# Same contract as `web_surface.FetchFn`: URL -> response dict or None.
FetchFn = Callable[[str], Optional[dict[str, Any]]]

# Conventional locations of a machine-readable spec, cheapest first.
OPENAPI_CANDIDATES: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v1/openapi.json",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
)

# HTTP methods a path item may declare. Anything else in a path item is
# metadata (summary, parameters, servers), not an operation.
_OPERATIONS: frozenset[str] = frozenset({"get", "post", "put", "patch", "delete"})

# Parameter locations worth injecting into: a header or cookie parameter is a
# different transport than the sender speaks, so it is left out.
_INJECTABLE_LOCATIONS: frozenset[str] = frozenset({"query", "formData"})

MAX_REF_DEPTH = 5


def _spec_prefix(spec: dict[str, Any], base: str) -> str:
    """Path prefix every route is mounted under, from OAS3 or Swagger 2.

    An absolute server URL contributes only its path: the host stays the target
    we were asked to scan, never one the document points elsewhere.
    """
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        first = servers[0]
        if isinstance(first, dict):
            url = first.get("url")
            if isinstance(url, str) and url:
                prefix = urlparse(url).path if "://" in url else url
                return "/" + prefix.strip("/") if prefix.strip("/") else ""
    base_path = spec.get("basePath")
    if isinstance(base_path, str) and base_path.strip("/"):
        return "/" + base_path.strip("/")
    return ""


def _resolve(spec: dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Follow a local `$ref` to the object it names, bounded against cycles."""
    if depth >= MAX_REF_DEPTH or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    target: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(target, dict) or part not in target:
            return {}
        target = target[part]
    return _resolve(spec, target, depth + 1)


def _schema_fields(spec: dict[str, Any], schema: Any) -> list[str]:
    """Top-level property names of a body schema.

    Only the top level: a nested object is not a flat parameter name, and the
    sender delivers a flat mapping.
    """
    resolved = _resolve(spec, schema)
    if not isinstance(resolved, dict):
        return []
    props = resolved.get("properties")
    if not isinstance(props, dict):
        return []
    return [name for name in props if isinstance(name, str)]


def _declared_params(spec: dict[str, Any], raw: Any) -> list[str]:
    """Names from a `parameters` list, keeping only injectable locations."""
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for entry in raw:
        param = _resolve(spec, entry)
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        location = param.get("in")
        if isinstance(name, str) and location in _INJECTABLE_LOCATIONS and name not in names:
            names.append(name)
    return names


def _endpoint(
    url: str,
    method: str,
    params: list[str],
    *,
    body_params: Optional[list[str]] = None,
    path_params: Optional[list[str]] = None,
    source: str = "",
) -> dict[str, Any]:
    """One endpoint record, with every key present whichever path built it.

    Three call sites assembled this shape by hand and each carried a different
    subset: the spec path set body_params, the bundle path did not, the
    well-known path set neither it nor path_params. Consumers then guessed the
    difference with `.get(key, []) or []`, and a field dropped at the source
    was indistinguishable from a field that legitimately had no value. Both
    path_params and source have been lost across this boundary before.
    """
    return {
        "url": url,
        "method": method,
        "params": list(params),
        "body_params": list(body_params or []),
        "path_params": list(path_params or []),
        "source": source,
    }


def _body_params(spec: dict[str, Any], operation: dict[str, Any]) -> list[str]:
    """Body field names, from an OAS3 requestBody or a Swagger 2 body param."""
    names: list[str] = []
    body = _resolve(spec, operation.get("requestBody"))
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict):
                    for name in _schema_fields(spec, media.get("schema")):
                        if name not in names:
                            names.append(name)
    raw = operation.get("parameters")
    if isinstance(raw, list):
        for entry in raw:
            param = _resolve(spec, entry)
            if isinstance(param, dict) and param.get("in") == "body":
                for name in _schema_fields(spec, param.get("schema")):
                    if name not in names:
                        names.append(name)
    return names


def _join(base: str, prefix: str, path: str) -> str:
    root = base.rstrip("/") + prefix
    tail = path.strip("/")
    return f"{root}/{tail}" if tail else root


_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _path_params(path: str) -> list[str]:
    """Names templated into the path itself.

    The document is not the authority here: a spec may leave a placeholder
    out of its `parameters` list while the route still refuses any request
    that leaves it unfilled. The template is the fact, so it is what we read.
    """
    names: list[str] = []
    for name in _PLACEHOLDER.findall(path):
        if name not in names:
            names.append(name)
    return names


def parse_openapi(spec: Any, base: str) -> list[dict[str, Any]]:
    """Endpoints declared by an OpenAPI 3 or Swagger 2 document.

    Returns the `web_surface` endpoint shape plus `body_params`, the subset of
    names the document says travel in the request body. That distinction is
    not cosmetic: a route can declare a required body on a GET, and sending
    those names as query parameters earns a validation error, never an answer.

    Parameter names come from the document; a path carrying a `{placeholder}`
    keeps the template in `url` and names the placeholder in `path_params`,
    because a value spliced into the path is as injectable as one carried on
    the query string. A caller must fill every placeholder before requesting:
    the template itself addresses no route.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    prefix = _spec_prefix(spec, base)

    endpoints: list[dict[str, Any]] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        path_names = _path_params(path)
        shared = _declared_params(spec, item.get("parameters"))
        for method, operation in item.items():
            if method.lower() not in _OPERATIONS or not isinstance(operation, dict):
                continue
            params = list(path_names)
            for name in shared:
                if name not in params:
                    params.append(name)
            for name in _declared_params(spec, operation.get("parameters")):
                if name not in params:
                    params.append(name)
            body = [name for name in _body_params(spec, operation) if name not in params]
            endpoints.append(
                _endpoint(
                    _join(base, prefix, path),
                    method.upper(),
                    params + body,
                    body_params=body,
                    path_params=path_names,
                    source="openapi",
                )
            )
    return endpoints


# A target may publish its API root in a Link header instead of at a
# conventional path (RFC 8288). WordPress does, and nothing else answers.
_LINK_ENTRY = re.compile(r"<([^>]+)>\s*;\s*(.*)")
_LINK_REL = re.compile(r'rel\s*=\s*"?([^";]+)"?')
API_REL_HINTS: tuple[str, ...] = ("api.w.org", "service-desc", "describedby")


def spec_url_from_link(headers: Any, base: str) -> Optional[str]:
    """The API root a `Link` header advertises, re-addressed to `base`.

    Only the path is taken. A target behind Docker names itself by its
    compose alias -- `Link: <http://target:9090/wp-json/>` -- which does not
    resolve outside that network, and following it would leave the host we
    were asked to scan. Same rule `_spec_prefix` already applies to an
    absolute server URL in a document.

    None when no entry declares an API relation: a `Link` to a stylesheet or
    a shortlink says nothing about a machine-readable surface.
    """
    if not isinstance(headers, dict):
        return None
    raw = headers.get("link") or headers.get("Link")
    if not isinstance(raw, str) or not raw.strip():
        return None
    for entry in raw.split(","):
        matched = _LINK_ENTRY.match(entry.strip())
        if matched is None:
            continue
        rel = _LINK_REL.search(matched.group(2) or "")
        if rel is None:
            continue
        value = rel.group(1).strip()
        if not any(hint in value for hint in API_REL_HINTS):
            continue
        path = urlparse(matched.group(1).strip()).path or "/"
        return base.rstrip("/") + "/" + path.strip("/") if path.strip("/") else base.rstrip("/")
    return None


_WP_PLACEHOLDER = re.compile(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>[^)]*\)")


def parse_wp_rest(spec: Any, base: str) -> list[dict[str, Any]]:
    """Endpoints declared by a WordPress REST index.

    A different shape for the same fact: routes rather than paths, and a
    regex group rather than a brace where a value goes. The group is rewritten
    to the brace form the rest of this module already speaks, so a consumer
    does not have to know which document a template came from.

    Parameter names are read per operation, not per route: one route declares
    several methods and each brings its own args, so merging the levels would
    hand a POST the names only a GET reads. Only the top level of args counts
    -- the nested properties of an array argument describe the items of a
    body, not names the route reads.
    """
    if not isinstance(spec, dict):
        return []
    routes = spec.get("routes")
    if not isinstance(routes, dict):
        return []
    prefix = urlparse(base).path.rstrip("/")
    root = base[: len(base) - len(prefix)].rstrip("/") if prefix else base.rstrip("/")

    endpoints: list[dict[str, Any]] = []
    for route, item in routes.items():
        if not isinstance(route, str) or not isinstance(item, dict):
            continue
        path_names = _WP_PLACEHOLDER.findall(route)
        templated = _WP_PLACEHOLDER.sub(lambda m: "{" + m.group(1) + "}", route)
        operations = item.get("endpoints")
        if not isinstance(operations, list):
            continue
        for operation in operations:
            if not isinstance(operation, dict):
                continue
            args = operation.get("args")
            names = list(path_names)
            if isinstance(args, dict):
                for name in args:
                    if isinstance(name, str) and name not in names:
                        names.append(name)
            for method in operation.get("methods") or []:
                if not isinstance(method, str) or method.lower() not in _OPERATIONS:
                    continue
                endpoints.append(
                    _endpoint(
                        _join(root, prefix, templated),
                        method.upper(),
                        names,
                        path_params=path_names,
                        source="wp-rest",
                    )
                )
    return endpoints


def fetch_openapi(
    base: str,
    fetch: FetchFn,
    candidates: tuple[str, ...] = OPENAPI_CANDIDATES,
) -> dict[str, Any]:
    """Probe conventional spec locations and parse the first real document.

    Returns {"spec_url", "endpoints"}; spec_url is None when nothing parsed, so
    a caller can tell "no spec published" from "spec published, no routes".
    """
    for candidate in candidates:
        url = base.rstrip("/") + candidate
        resp = fetch(url)
        if not isinstance(resp, dict):
            continue
        status = resp.get("status")
        if isinstance(status, int) and status >= 400:
            continue
        body = resp.get("body")
        if not isinstance(body, str) or not body.strip():
            continue
        try:
            spec = json.loads(body)
        except (ValueError, TypeError):
            continue
        if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
            continue
        return {"spec_url": url, "endpoints": parse_openapi(spec, base)}
    return {"spec_url": None, "endpoints": []}


# --- JS bundle route extraction ---------------------------------------------

# Bundle budget: a route table repeats itself, and a build ships more chunks
# than a recon pass should download.
MAX_SCRIPTS = 8
# A bundle names its whole API, and a real SPA has more than forty calls in
# it: Juice Shop alone yields eighty-five. The cap survives a pathological
# bundle rather than sampling a normal one -- set too low it truncates the
# surface silently, and an endpoint that fell off the end looks exactly like
# an endpoint that does not exist.
MAX_ROUTES = 200
MAX_SCRIPT_BYTES = 3_000_000

# A quoted absolute path, with any query string it carries.
#
# A bundled SPA rarely writes the path as one flat literal: the host comes
# from a field and the identifiers come from variables, so the route reaches
# the bundle as a template literal. Allowing a leading interpolation (the host
# base) and further ones inside the path is what makes those routes visible at
# all -- requiring a literal slash right after the quote hides every call an
# Angular or React service makes through its own base URL.
_INTERP = r"\$\{[^{}]*\}"
_ROUTE_LITERAL = re.compile(
    r"""['"`](?:""" + _INTERP + r""")?"""
    r"""(/(?:[A-Za-z0-9_\-./]|""" + _INTERP + r""")*)"""
    r"""((?:\?(?:[A-Za-z0-9_\-=&%.]|""" + _INTERP + r""")*)?)['"`]"""
)

# Static files a build references by path; requesting them proves nothing.
_ASSET_SUFFIXES: tuple[str, ...] = (
    ".js",
    ".mjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".html",
    ".htm",
)

# Transport settings of a fetch/axios options object, never app fields.
_HARD_OPTIONS: frozenset[str] = frozenset(
    {
        "method",
        "headers",
        "credentials",
        "mode",
        "cache",
        "signal",
        "redirect",
        "referrer",
        "referrerPolicy",
        "integrity",
        "keepalive",
        "responseType",
        "timeout",
        "withCredentials",
        "baseURL",
        "url",
        # An Angular service writes no `method:`, so its options bag is only
        # recognisable by these: they name how the response is delivered, and
        # a server is never asked for a field called `reportProgress`.
        "observe",
        "reportProgress",
        "context",
        "transferCache",
    }
)

# Names that mean "the payload" inside an options object but are ordinary
# fields anywhere else. Dropped only when the object is provably options.
_SOFT_OPTIONS: frozenset[str] = frozenset({"body", "data", "params", "query"})

# How far around a literal to look for the call that uses it.
_WINDOW = 160

_OBJECT_KEY = re.compile(r"""[{,]\s*['"]?([A-Za-z_$][A-Za-z0-9_$]*)['"]?\s*:""")
_CALL_METHOD = re.compile(r"""\.(get|post|put|patch|delete)\s*\($""", re.IGNORECASE)
_OPTION_METHOD = re.compile(r"""method\s*:\s*['"]([A-Za-z]+)['"]""")


def _is_route(path: str) -> bool:
    """Whether a quoted path is plausibly a request target, not an asset.

    Interpolation is judged by `_normalise_interpolated`, not here: a `${id}`
    inside a path names a path parameter, which is a route we can attack, so
    rejecting it outright would discard exactly the templated endpoints the
    exploit side now knows how to fill.
    """
    if len(path) < 2 or path.startswith("//"):
        return False
    if "{" in path and "${" not in path:
        return False
    return not path.lower().endswith(_ASSET_SUFFIXES)


_INTERP_RE = re.compile(r"\$\{([^{}]*)\}")
_IDENT_TAIL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")


def _interp_name(expression: str, index: int) -> str:
    """A parameter name for one interpolation, from its trailing identifier.

    `${this.userId}` names userId; an expression ending in a call or an index
    names nothing usable, so the position gets a positional name instead. The
    name only has to be stable and unique within the path -- it labels a slot
    to inject into, it is not a contract with the server.
    """
    match = _IDENT_TAIL.search(expression)
    return match.group(1) if match else f"p{index}"


def _normalise_interpolated(path: str) -> Optional[str]:
    """Rewrite `${expr}` segments as `{name}` placeholders, or reject the path.

    Two interpolations with nothing between them cannot be told apart once
    filled -- the request would address a path neither value ever formed -- so
    such a literal is dropped rather than guessed at.
    """
    if "${" not in path:
        return path
    if re.search(r"\}\s*\$\{", path):
        return None
    # A path whose first segment is the interpolation has lost its prefix: the
    # base was concatenated elsewhere ("host = server + '/rest/products'") and
    # never appears in the literal. What is left addresses the site root, so
    # requesting it tests a route the application does not serve.
    if path.startswith("${") or path.startswith("/${"):
        return None
    seen: set[str] = set()

    def _replace(match: re.Match[str]) -> str:
        name = _interp_name(match.group(1), len(seen))
        while name in seen:
            name = f"{name}_{len(seen)}"
        seen.add(name)
        return "{" + name + "}"

    return _INTERP_RE.sub(_replace, path)


def _query_names(query: str) -> list[str]:
    """Parameter names present on the literal itself."""
    names: list[str] = []
    for pair in query.lstrip("?").split("&"):
        name = pair.split("=")[0].strip()
        if "${" in name:
            continue
        if name and name not in names:
            names.append(name)
    return names


def _call_window(text: str, end: int) -> str:
    """Text belonging to the call that used the literal, and nothing after it.

    Minified output packs unrelated calls onto one line, so the window ends
    where this call's parentheses close: without that bound, the fields of the
    next request leak onto this route.
    """
    depth = 0
    out: list[str] = []
    for ch in text[end : end + _WINDOW]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == ";" and depth == 0:
            break
        out.append(ch)
    return "".join(out)


def _object_keys(window: str) -> list[str]:
    """Application field names from object literals next to the call.

    Nested braces are read too, so a `JSON.stringify({...})` payload
    contributes its fields. A `method:` key proves the object is a request
    options bag, and only then are payload-wrapper names dropped -- elsewhere
    `body` is as likely to be a real field as any other.
    """
    names_present = _OBJECT_KEY.findall(window)
    is_options = _OPTION_METHOD.search(window) is not None
    # A lone `params` key is the request's query bag, never a field: an object
    # whose only member is named after the transport is the transport.
    if names_present == ["params"]:
        return []
    names: list[str] = []
    for name in names_present:
        if name in _HARD_OPTIONS or (is_options and name in _SOFT_OPTIONS):
            continue
        if name not in names:
            names.append(name)
    return names


def _method_for(before: str, window: str) -> str:
    """Verb the call uses, from `.post(` before it or `method:` after it."""
    call = _CALL_METHOD.search(before.rstrip())
    if call:
        return call.group(1).upper()
    option = _OPTION_METHOD.search(window)
    if option:
        return option.group(1).upper()
    return "GET"


class _ScriptParser(HTMLParser):
    """Collects `<script src=...>` locations from one HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag != "script":
            return
        attr = {k.lower(): (v or "") for k, v in attrs}
        src = attr.get("src")
        if src:
            self.sources.append(src)


def script_urls(html: str, page_url: str, base: str, limit: int = MAX_SCRIPTS) -> list[str]:
    """Same-origin bundle URLs referenced by a page, in document order."""
    parser = _ScriptParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # malformed HTML must not abort discovery
        pass

    origin = urlparse(base)
    found: list[str] = []
    for src in parser.sources:
        url = urljoin(page_url, src).split("#")[0]
        parts = urlparse(url)
        if (parts.scheme, parts.hostname, parts.port) != (
            origin.scheme,
            origin.hostname,
            origin.port,
        ):
            continue
        if url not in found:
            found.append(url)
        if len(found) >= limit:
            break
    return found


def routes_from_javascript(text: str, max_routes: int = MAX_ROUTES) -> list[dict[str, Any]]:
    """Request paths a bundle names literally, with the fields sent alongside.

    A bundled SPA calls its own API by string literal, so the route table the
    empty HTML shell never mentions sits in the bundle in plain text. Parameter
    names come from the query string on the literal or from the object literal
    passed to the call; nothing else is inferred.
    """
    routes: dict[tuple[str, str], dict[str, Any]] = {}
    for match in _ROUTE_LITERAL.finditer(text):
        path, query = match.group(1), match.group(2)
        if not _is_route(path):
            continue
        normalised = _normalise_interpolated(path)
        if normalised is None:
            continue
        path = normalised
        path_names = _path_params(path)
        window = _call_window(text, match.end())
        method = _method_for(text[max(0, match.start() - _WINDOW) : match.start()], window)
        params = list(path_names)
        for name in _query_names(query):
            if name not in params:
                params.append(name)
        for name in _object_keys(window):
            if name not in params:
                params.append(name)
        slot = routes.setdefault(
            (path, method),
            {
                "path": path,
                "method": method,
                "params": [],
                "path_params": path_names,
                "source": "js-route",
            },
        )
        for name in params:
            if name not in slot["params"]:
                slot["params"].append(name)
        if len(routes) >= max_routes:
            break
    return list(routes.values())


# A bundled service keeps its base path in a field and appends the rest at the
# call site: `host=this.hostServer+"/rest/user"` once, then
# `this.http.post(this.host+"/erasure-request",...)` wherever it is used. The
# path never exists as one literal, so a literal-only reader sees neither half.
# On Juice Shop this hides eighteen base paths -- more endpoints than the
# literal reader finds in total.
_BASE_DECL = re.compile(
    r"""([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;{}=]*?\+\s*['"`](/[A-Za-z0-9_\-./]*)['"`]"""
)

# A call whose target is that field, with or without a tail appended.
_BASE_CALL = re.compile(
    r"""\.(get|post|put|patch|delete)\s*\(\s*(?:this\.)?"""
    r"""([A-Za-z_$][A-Za-z0-9_$]*)"""
    r"""(?:\s*\+\s*['"`](/[A-Za-z0-9_\-./]*)['"`])?""",
    re.IGNORECASE,
)


def _base_at(declarations: list[tuple[int, str, str]], field: str, position: int) -> Optional[str]:
    """The base this call was written under: nearest declaration of the field.

    Bundlers emit a class as one run of text, so the declaration a call means
    is the last one for that field before it. Pairing every base with every
    tail instead would invent paths no service ever calls -- ninety guesses
    where sixteen calls exist.
    """
    best: Optional[str] = None
    for at, name, base in declarations:
        if at < position and name == field:
            best = base
    return best


def routes_from_concatenated_base(text: str, max_routes: int = MAX_ROUTES) -> list[dict[str, Any]]:
    """Request paths a bundle assembles from a field plus a literal tail.

    Reported paths are still guesses: like every synthesized name here, one
    enters the surface only once the target answers it apart from its own
    baseline.
    """
    declarations = [(m.start(), m.group(1), m.group(2)) for m in _BASE_DECL.finditer(text)]
    if not declarations:
        return []
    routes: dict[tuple[str, str], dict[str, Any]] = {}
    for match in _BASE_CALL.finditer(text):
        method, field, tail = match.group(1).upper(), match.group(2), match.group(3)
        base = _base_at(declarations, field, match.start())
        if base is None:
            continue
        path = base + (tail or "")
        if path.endswith("/") and len(path) > 1:
            path = path[:-1]
        if not _is_route(path):
            continue
        window = _call_window(text, match.end())
        slot = routes.setdefault(
            (path, method),
            {
                "path": path,
                "method": method,
                "params": [],
                "path_params": _path_params(path),
                "source": "js-route",
            },
        )
        for name in _object_keys(window):
            if name not in slot["params"]:
                slot["params"].append(name)
        if len(routes) >= max_routes:
            break
    return list(routes.values())


def _merge_route(collected: dict[tuple[str, str], dict[str, Any]], route: dict[str, Any]) -> None:
    """Fold one route into the table, keeping every name either source found.

    A path reached by both readers must not lose the parameters only one of
    them saw, so names are added rather than the later route replacing the
    earlier one.

    Only the declared names need folding. Both readers derive path_params from
    the path itself, so two routes under one key already agree on them, and the
    concatenating reader cannot produce a templated path at all: neither `$`
    nor `{` is in the character class its base and tail are matched with.
    """
    slot = collected.setdefault((route["path"], route["method"]), route)
    for name in route["params"]:
        if name not in slot["params"]:
            slot["params"].append(name)


def fetch_js_routes(
    base: str,
    fetch: FetchFn,
    html: str,
    page_url: Optional[str] = None,
    max_scripts: int = MAX_SCRIPTS,
    max_routes: int = MAX_ROUTES,
) -> dict[str, Any]:
    """Read the page's own bundles and return the routes they name.

    Returns {"scripts", "endpoints"} where endpoints carry absolute URLs in the
    `web_surface` shape; an endpoint may legitimately have no parameters, and
    the caller decides what an unparameterised route is worth.
    """
    origin = page_url or base.rstrip("/") + "/"
    collected: dict[tuple[str, str], dict[str, Any]] = {}
    scripts: list[str] = []

    for url in script_urls(html, origin, base, limit=max_scripts):
        resp = fetch(url)
        if not isinstance(resp, dict):
            continue
        body = resp.get("body")
        if not isinstance(body, str) or not body:
            continue
        scripts.append(url)
        text = body[:MAX_SCRIPT_BYTES]
        # One bundle names its API two ways at once: as whole literals, and as
        # a base field with the rest appended at the call. The same path can
        # arrive by both, so they merge into one table rather than two lists.
        for route in routes_from_javascript(
            text, max_routes=max_routes
        ) + routes_from_concatenated_base(text, max_routes=max_routes):
            _merge_route(collected, route)

    endpoints = [
        _endpoint(
            urljoin(base.rstrip("/") + "/", route["path"].lstrip("/")),
            route["method"],
            route["params"],
            path_params=route.get("path_params", []),
            source="js-route",
        )
        for route in collected.values()
    ]
    return {"scripts": scripts, "endpoints": endpoints}


# --- merged API surface ------------------------------------------------------

# A last resort, kept deliberately short: these are conventions, not evidence,
# and each one costs a request against a live target.
WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/health",
    "/status",
    "/metrics",
    "/actuator",
    "/admin",
    "/debug",
)

# A path that answers 401/403 exists and is guarded -- worth reporting. A 404
# or a dead connection is absence, and absence is not a finding.
_PRESENT_STATUSES: frozenset[int] = frozenset({401, 403})


def probe_well_known(
    base: str,
    fetch: FetchFn,
    paths: tuple[str, ...] = WELL_KNOWN_PATHS,
) -> list[dict[str, Any]]:
    """Conventional paths that answer, as parameterless endpoints."""
    found: list[dict[str, Any]] = []
    for path in paths:
        url = base.rstrip("/") + path
        resp = fetch(url)
        if not isinstance(resp, dict):
            continue
        status = resp.get("status")
        if not isinstance(status, int):
            continue
        if status < 400 or status in _PRESENT_STATUSES:
            found.append(_endpoint(url, "GET", [], source="well-known"))
    return found


# Parameter names a route may read without ever declaring them, ordered by how
# often each drew a different answer from a measured target. Names that drew
# nothing anywhere (search, user, file) are left out: each costs one request
# per route to establish nothing.
SYNTHETIC_PARAM_NAMES: tuple[str, ...] = ("q", "id", "page", "name")

# The probe asks whether a value is read at all, not whether it is dangerous,
# so it carries nothing hostile.
_PROBE_VALUE = "1"


def _with_param(url: str, name: str) -> str:
    """`url` carrying one more query argument, whatever it already carries."""
    separator = "&" if urlparse(url).query else "?"
    return url + separator + urlencode({name: _PROBE_VALUE})


def _answer(resp: Optional[dict[str, Any]]) -> Optional[tuple[int, str]]:
    """(status, body) of a reply we can compare, or None if there was none."""
    if not isinstance(resp, dict):
        return None
    status = resp.get("status")
    body = resp.get("body")
    if not isinstance(status, int) or not isinstance(body, str):
        return None
    return (status, body)


def probe_route_params(
    routes: list[dict[str, Any]],
    fetch: FetchFn,
    names: tuple[str, ...] = SYNTHETIC_PARAM_NAMES,
    max_probes: int = 300,
) -> list[dict[str, Any]]:
    """Routes that read a parameter they never declared, carrying that name.

    A route with nothing to inject is a dead end for exploitation, yet a REST
    layer commonly accepts a filter argument its own documents omit. Sending
    one and comparing the answer against the route's baseline separates the
    two: the name is synthesized, the evidence that it is read is not.

    Status counts as part of the answer. A parameter that turns a 200 into a
    500 is being read -- that is the shape of an injection reaching a query --
    and comparing bodies alone would file it as ignored.

    Only a route that answers 200 is probed. Behind a 401 or a 500 the reply
    is the same refusal whatever we append, so the comparison proves nothing
    and spends the budget to do so.

    A route whose two baselines differ answers identical requests differently
    -- a captcha, a timestamp, a counter -- and cannot be measured this way,
    so it is dropped rather than credited with a difference we did not cause.
    That second baseline is spent only once a difference has already appeared,
    which on a real target is a handful of routes rather than every one.

    Answers are compared as the fetcher returns them, truncated at its own
    limit; a route differing only past that limit reads as inert.

    Reading a parameter is not the same as being vulnerable through it. On a
    measured target this promoted four routes whose REST layer filters on an
    undeclared name, and every one of them answered a quoted value with a
    normal page: the layer parameterises its queries. The gain is a surface
    exploitation can now reach, not a finding. Cost on a
    surface the size of Juice Shop measured around 255 requests, which is why
    this budget is separate from the one exploitation spends.
    """
    promoted: list[dict[str, Any]] = []
    probes = 0
    for route in routes:
        if probes >= max_probes:
            break
        url = route.get("url", "")
        if not url or (route.get("method") or "GET").upper() != "GET" or "{" in url:
            continue
        probes += 1
        baseline = _answer(fetch(url))
        if baseline is None or baseline[0] != 200:
            continue
        for name in names:
            if probes >= max_probes:
                break
            probes += 1
            probed = _answer(fetch(_with_param(url, name)))
            if probed is None or probed == baseline:
                continue
            probes += 1
            if _answer(fetch(url)) != baseline:
                break
            found = dict(route)
            found["params"] = [name]
            found["source"] = "probed"
            promoted.append(found)
            break
    return promoted


def discover_api_surface(
    base: str,
    fetch: FetchFn,
    html: str = "",
    page_url: Optional[str] = None,
    probe_conventions: bool = True,
    probe_routes: bool = False,
    max_route_probes: int = 300,
) -> dict[str, Any]:
    """Collect the API surface a target publishes, from cheapest source first.

    A spec is authoritative, a bundle is evidence, and a conventional path is
    neither -- so the convention probe runs only when the first two produced
    nothing, keeping the request cost of a guess out of the normal path.

    Returns {"endpoints", "routes", "spec_url", "scripts"}. Endpoints carry
    parameters and are what exploitation can act on; routes are paths that
    exist with nothing to inject, kept separate so a report can name them
    without exploitation wasting requests on them.

    `probe_routes` asks each route whether it reads a parameter it never
    declared, and moves the ones that do into `endpoints`. It is off by
    default because it costs a request per route to establish a negative:
    against a REST layer that reads undeclared filters it found four more
    injectable endpoints, and against an API that declares everything it
    finds nothing and spends the budget saying so.
    """
    spec = fetch_openapi(base, fetch)
    collected: list[dict[str, Any]] = list(spec["endpoints"])

    js = (
        fetch_js_routes(base, fetch, html, page_url=page_url)
        if html
        else {"scripts": [], "endpoints": []}
    )
    collected.extend(js["endpoints"])

    if probe_conventions and not any(e["params"] for e in collected):
        collected.extend(probe_well_known(base, fetch))

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for endpoint in collected:
        key = (endpoint["url"].rstrip("/"), endpoint["method"])
        slot = merged.get(key)
        if slot is None:
            merged[key] = dict(endpoint)
            continue
        for name in endpoint["params"]:
            if name not in slot["params"]:
                slot["params"].append(name)
        # Only the spec path fills body_params, and one document cannot declare
        # the same (path, method) twice, so a second record for this key never
        # brings any: the branch that merged them was unreachable and its
        # setdefault guarded against a shape the constructor now rules out.
        # Measured, not reasoned: a spec and a bundle describing the same POST
        # produce one record whose body fields come from the spec alone.

    endpoints = [e for e in merged.values() if e["params"]]
    routes = [e for e in merged.values() if not e["params"]]

    if probe_routes and routes:
        promoted = probe_route_params(routes, fetch, max_probes=max_route_probes)
        moved = {(e["url"], e["method"]) for e in promoted}
        routes = [r for r in routes if (r["url"], r["method"]) not in moved]
        endpoints.extend(promoted)

    return {
        "endpoints": endpoints,
        "routes": routes,
        "spec_url": spec["spec_url"],
        "scripts": js["scripts"],
    }
