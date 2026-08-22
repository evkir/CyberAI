"""Every helper in core/security must have a caller in production code.

W1-D3.2. C1 in STANDOFF-KEY is the shape this guards against: a package of
sanitisers with unit tests, a green CI, and no call site. A unit test proves
a function works; only a call site proves the product uses it.

This is a ratchet, not a pass/fail wall. Three helpers are still unwired and
are listed below with the reason each one is still here. The test fails when
a *new* unwired helper appears, when a listed one gets wired (update the
list), or when a listed one disappears (remove it from the list). It cannot
be satisfied by deleting the evidence.

Known limitation: a helper called only by another unwired helper counts as
wired. A chain of dead functions calling each other would pass. The ratchet
below is what catches that case in practice, because the chain has to start
somewhere and that entry point is what shows up as unwired.
"""

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
SECURITY = REPO / "cyberai" / "core" / "security"
PRODUCTION = REPO / "cyberai"

# name -> why it is still unwired. Measured 23.08.2026.
KNOWN_UNWIRED = {
    "scan_messages": (
        "Duplicate of the loop in TrustGuard.inspect with the threshold "
        "hardcoded: detect_injection flags at >= 25 and scan_messages "
        "filters on that flag, so a configurable threshold of 50 cannot be "
        "expressed through it. Wiring it would mean re-deriving the score "
        "from its details payload."
    ),
    "redact_sensitive": (
        "The only insertion point is JsonFormatter.format, before the "
        "signature is computed. Measured against 1539 real audit lines from "
        "three archived trails: the function changes nothing in any of them. "
        "No demonstrated input."
    ),
    "validate_json_output": (
        "Guards the model's output, not its input, so it is outside the W1 "
        "trust boundary. structured_call already validates against a JSON "
        "schema. No consumer identified."
    ),
}


def _public_module_functions(package: pathlib.Path) -> dict[str, pathlib.Path]:
    """Module-level public defs only: methods and helpers are not the surface."""
    found: dict[str, pathlib.Path] = {}
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    found[node.name] = path
    return found


def _own_body_span(name: str, path: pathlib.Path) -> tuple[int, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node.lineno, node.end_lineno or node.lineno
    raise AssertionError(f"{name} not found at module level in {path}")


def _call_sites(root: pathlib.Path) -> dict[str, set[tuple[str, int]]]:
    sites: dict[str, set[tuple[str, int]]] = {}
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            else:
                continue
            sites.setdefault(name, set()).add((str(path), node.lineno))
    return sites


def _unwired() -> set[str]:
    defined = _public_module_functions(SECURITY)
    sites = _call_sites(PRODUCTION)
    dead = set()
    for name, home in defined.items():
        start, end = _own_body_span(name, home)
        external = {
            site
            for site in sites.get(name, set())
            if not (site[0] == str(home) and start <= site[1] <= end)
        }
        if not external:
            dead.add(name)
    return dead


@pytest.mark.architecture
def test_no_new_security_helper_goes_unwired():
    new = _unwired() - set(KNOWN_UNWIRED)
    assert not new, (
        "security helpers defined with no caller in cyberai/: "
        f"{sorted(new)}. Wire it, or add it to KNOWN_UNWIRED with the "
        "measurement that says why it stays."
    )


@pytest.mark.architecture
def test_the_unwired_list_does_not_go_stale():
    wired_now = set(KNOWN_UNWIRED) - _unwired()
    assert not wired_now, f"these are wired now and must leave KNOWN_UNWIRED: {sorted(wired_now)}"


@pytest.mark.architecture
def test_every_listed_helper_still_exists():
    defined = set(_public_module_functions(SECURITY))
    gone = set(KNOWN_UNWIRED) - defined
    assert not gone, f"listed but no longer defined, drop from KNOWN_UNWIRED: {sorted(gone)}"
