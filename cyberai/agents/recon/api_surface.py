"""API attack-surface discovery for targets whose HTML carries nothing to follow.

A single-page application serves an empty shell: no anchors, no forms, nothing
an HTML crawler can act on. Its real surface is published elsewhere -- in an
OpenAPI document, in the route table compiled into a JS bundle, or behind a
handful of conventional paths. This module reads those sources and returns the
endpoint shape `web_surface` already produces, so exploitation needs no change.

Everything here is read from something the target itself published; no route
and no parameter name is invented. An operation whose path still holds a
template placeholder is skipped rather than filled with a guessed value.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional
from urllib.parse import urlparse

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


def parse_openapi(spec: Any, base: str) -> list[dict[str, Any]]:
    """Endpoints declared by an OpenAPI 3 or Swagger 2 document.

    Returns the `web_surface` endpoint shape. Parameter names come from the
    document; a path carrying a `{placeholder}` is dropped, because requesting
    the template would hit a route that does not exist.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    prefix = _spec_prefix(spec, base)

    endpoints: list[dict[str, Any]] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict) or "{" in path:
            continue
        shared = _declared_params(spec, item.get("parameters"))
        for method, operation in item.items():
            if method.lower() not in _OPERATIONS or not isinstance(operation, dict):
                continue
            params = list(shared)
            for name in _declared_params(spec, operation.get("parameters")) + _body_params(
                spec, operation
            ):
                if name not in params:
                    params.append(name)
            endpoints.append(
                {
                    "url": _join(base, prefix, path),
                    "method": method.upper(),
                    "params": params,
                    "source": "openapi",
                }
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
