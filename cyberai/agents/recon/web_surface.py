"""
HTTP attack-surface discovery.

Exploitation needs somewhere to inject: a URL, a parameter name, a method.
Port scanning gives us "80/tcp open http" and nothing to act on, so this module
walks a web target shallowly and returns the injectable points it finds --
query parameters on discovered links and input fields on discovered forms.

Depth is deliberately small (default 1) and scope is same-origin only: this is
reconnaissance for a pentest pipeline, not a site mirror, and an unbounded
crawler on a live engagement is both slow and rude.

Follows the prober-injection contract used by `llm_detector`: callers may pass
a `FetchFn` for tests, otherwise a live httpx fetcher is used.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

DEFAULT_TIMEOUT = 5.0
DEFAULT_DEPTH = 1
MAX_PAGES = 25
MAX_BODY = 200_000

# A fetcher maps a URL to {"status", "headers", "body", "url"} or None on failure.
FetchFn = Callable[[str], Optional[dict[str, Any]]]


def _default_fetcher(timeout: float) -> FetchFn:
    """Return a fetcher that issues a GET via httpx, mirroring llm_detector."""

    def _fetch(url: str) -> Optional[dict[str, Any]]:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                r = client.get(url)
                return {
                    "status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": r.text[:MAX_BODY],
                    "url": str(r.url),
                }
        except Exception:
            return None

    return _fetch


class _SurfaceParser(HTMLParser):
    """Collects hrefs and form definitions from one HTML page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: Optional[dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"])
        elif tag == "form":
            self._form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method") or "GET").upper(),
                "params": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = attr.get("name")
            if name and attr.get("type", "").lower() != "submit":
                self._form["params"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:  # flush an unclosed trailing <form>
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


def normalize_base(target: str) -> str:
    """Accept a bare host, host:port, or full URL and return a base URL."""
    t = target.strip()
    if not re.match(r"^https?://", t):
        t = f"http://{t}"
    return t.rstrip("/")


def _same_origin(candidate: str, base: str) -> bool:
    c, b = urlparse(candidate), urlparse(base)
    return (c.scheme, c.hostname, c.port) == (b.scheme, b.hostname, b.port)


# "GET /ping?host=" or "POST /login username,password" -- the shape API-style
# index pages use to advertise their own routes.
_HINT_QUERY = re.compile(r"(/[A-Za-z0-9_\-/.]*)\?([A-Za-z_][A-Za-z0-9_]*)=")
_HINT_FORM = re.compile(r"(GET|POST)\s+(/[A-Za-z0-9_\-/.]*)\s+([A-Za-z_][A-Za-z0-9_,\s]*)")


def _hint_endpoints(body: str) -> list[tuple[str, str, list[str]]]:
    """Routes an app advertises about itself, as (method, path, params).

    The path matters as much as the parameter name: a hint read on the index
    page describes a *different* route, so attributing the parameter to the
    index would send every later request to the wrong place.
    """
    found: dict[tuple[str, str], list[str]] = {}
    for path, param in _HINT_QUERY.findall(body):
        found.setdefault(("GET", path), []).append(param)
    for method, path, raw in _HINT_FORM.findall(body):
        params = [p.strip() for p in raw.split(",") if p.strip()]
        if params:
            found.setdefault((method, path), []).extend(params)
    return [(m, p, names) for (m, p), names in found.items()]


def discover_surface(
    target: str,
    fetcher: Optional[FetchFn] = None,
    depth: int = DEFAULT_DEPTH,
    timeout: float = DEFAULT_TIMEOUT,
    max_pages: int = MAX_PAGES,
) -> dict[str, Any]:
    """Walk a web target and return its injectable points.

    Returns {"base_url", "reachable", "endpoints": [...], "pages_fetched"} where
    each endpoint is {"url", "method", "params": [...], "source"}. An
    unreachable target yields reachable=False and no endpoints -- never a guess.
    """
    base = normalize_base(target)
    fetch = fetcher or _default_fetcher(timeout)

    seen_urls: set[str] = set()
    queue: list[tuple[str, int]] = [(base + "/", 0)]
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    pages = 0
    reachable = False

    def _record(url: str, method: str, params: list[str], source: str) -> None:
        clean = url.split("#")[0]
        key = (clean.split("?")[0], method)
        if not params:
            return
        slot = endpoints.setdefault(
            key, {"url": clean.split("?")[0], "method": method, "params": [], "source": source}
        )
        for p in params:
            if p not in slot["params"]:
                slot["params"].append(p)

    while queue and pages < max_pages:
        url, level = queue.pop(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        resp = fetch(url)
        if resp is None:
            continue
        reachable = True
        pages += 1
        body = resp.get("body") or ""
        if not isinstance(body, str):
            body = str(body)

        # Query parameters already present on the fetched URL are injectable.
        qs = parse_qs(urlparse(url).query)
        _record(url, "GET", list(qs), "url-query")

        # Routes the page advertises about itself, resolved against this page.
        for method, path, names in _hint_endpoints(body):
            hinted = urljoin(url, path)
            if _same_origin(hinted, base):
                _record(hinted, method, names, "hint")

        parser = _SurfaceParser()
        try:
            parser.feed(body)
            parser.close()
        except Exception:  # malformed HTML must not abort discovery
            pass

        for form in parser.forms:
            action = urljoin(url, form["action"] or "")
            if _same_origin(action, base):
                _record(action, form["method"], form["params"], "form")

        if level < depth:
            for href in parser.links:
                link = urljoin(url, href).split("#")[0]
                if not _same_origin(link, base) or link in seen_urls:
                    continue
                queue.append((link, level + 1))
                _record(link, "GET", list(parse_qs(urlparse(link).query)), "link")

    return {
        "base_url": base,
        "reachable": reachable,
        "pages_fetched": pages,
        "endpoints": list(endpoints.values()),
    }
