"""A parameter named for a URL may not be fed a literal that is not one.

The day-36 defect was a test passing a bare host where production passes a
URL. The detector written on day 40 cannot see that form and says so in its
own docstring: it reads the body of the called function for a boundary --
`Path()`, `urlparse()`, an argv -- and that function compared its parameter
against strings and touched no boundary. Where the body says nothing, the name
of the parameter is the only declaration of shape left.

So this reads the name. A parameter called `url`, `uri`, `endpoint` or one of
their compounds is fed literals that carry a scheme; a literal without one is
a violation unless it is named below with its reason. Parameters called `host`
are deliberately outside the rule: fifteen call sites feed them a bare host and
every one is right, so a rule covering them would report noise, not defects.

The resolver is the one from the day-40 detector, imported rather than copied,
so a callee is reached through imports and receiver classes and `probe` in a
test does not match `probe` anywhere in the package. What that resolver cannot
see, this cannot either: an argument assembled into a variable or an f-string
is not a literal and is not examined. Measured on this tree: 2079 calls
resolved, 58 literals examined under the rule, 5 violations, all allowed.
"""

from __future__ import annotations

import importlib.util
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
_DETECTOR = REPO / "tests" / "architecture" / "test_the_tests_use_the_shape_production_uses.py"


def _day40():
    """The day-36 form is defined by what this detector cannot see."""
    spec = importlib.util.spec_from_file_location("_shape_from_body", _DETECTOR)
    assert spec and spec.loader, _DETECTOR
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Names that declare a URL. `host` is excluded on purpose; see the docstring.
_URL_PARAMS = frozenset(
    {"url", "uri", "base_url", "target_url", "server_url", "api_url", "webhook_url", "endpoint"}
)

# Violations kept with their reason. An MCP endpoint is a URL or the command
# line of a stdio server, so these five are the second form, not a wrong one.
ALLOWED = {
    ("cyberai/mcp/client_probe.py::probe", "endpoint", "cyberai_nonexistent_binary_xyz123"),
    ("cyberai/agents/mcp_scan/attestation.py::assess_attestation", "endpoint", "python server.py"),
    ("cyberai/mcp/auth_metadata.py::probe_auth_metadata", "endpoint", "python3 -m server"),
    ("cyberai/agents/mcp_scan/exposure.py::assess_exposure", "endpoint", "python -m server"),
    ("cyberai/agents/mcp_scan/mst_bridge.py::build_target", "endpoint", "python3 server.py"),
}

# Measured: 58 literals examined, the largest single suite contributing 15.
# The floor sits below the remainder, so losing the largest suite still leaves
# the guard reporting rather than silent.
_EXAMINED_FLOOR = 40


def scan(root: pathlib.Path) -> tuple[set[tuple[str, str, str]], int]:
    """Violations under `root`, and how many literals the rule examined."""
    module = _day40()
    funcs, classes = module._index(root)
    violations: set[tuple[str, str, str]] = set()
    examined = 0
    for path in sorted((root / "tests").rglob("*.py")):
        for fn, call in module._resolve(path, funcs, classes):
            for param, literal in module._literals(fn, call):
                if param.lower() not in _URL_PARAMS:
                    continue
                examined += 1
                if "://" not in literal:
                    violations.add((fn.key, param, literal))
    return violations, examined


def _plant(root: pathlib.Path) -> None:
    """A callee whose body declares no shape, fed a bare host by its test."""
    package = root / "cyberai" / "agents"
    package.mkdir(parents=True)
    (root / "cyberai" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "tool.py").write_text(
        "def fetch(url: str) -> str:\n"
        "    if url in ('', 'none'):\n"
        "        return ''\n"
        "    return url.split('?')[0]\n",
        encoding="utf-8",
    )
    suite = root / "tests"
    suite.mkdir()
    (suite / "test_planted.py").write_text(
        "from cyberai.agents.tool import fetch\n"
        "\n"
        "\n"
        "def test_bare_host():\n"
        "    assert fetch('api.acme.com') == 'api.acme.com'\n"
        "\n"
        "\n"
        "def test_real_url():\n"
        "    assert fetch('http://api.acme.com/x?y=1') == 'http://api.acme.com/x'\n",
        encoding="utf-8",
    )


def test_no_test_feeds_a_url_parameter_something_without_a_scheme() -> None:
    violations, _ = scan(REPO)
    unexplained = violations - ALLOWED
    assert unexplained == set(), (
        "a parameter named for a URL was fed a literal without a scheme; give "
        "the call the real shape, or add it to ALLOWED with the reason: "
        + repr(sorted(unexplained))
    )


def test_every_allowed_entry_is_still_earned() -> None:
    """An allowlist entry that no longer fires is a claim nobody re-checks."""
    violations, _ = scan(REPO)
    assert ALLOWED, "an empty allowlist makes the check above vacuous"
    stale = ALLOWED - violations
    assert stale == set(), "remove these from ALLOWED, they no longer fire: " + repr(sorted(stale))


def test_the_rule_examines_more_than_the_largest_suite() -> None:
    """A rule that examines nothing reports nothing and looks clean."""
    _, examined = scan(REPO)
    assert examined >= _EXAMINED_FLOOR, (
        f"only {examined} literals reached the rule — the resolver or the name "
        "set is broken, not the suite"
    )


def test_a_planted_bare_host_is_caught_and_a_real_url_is_not(tmp_path: pathlib.Path) -> None:
    """The guard is measured against known-bad input, not trusted on silence."""
    _plant(tmp_path)
    violations, examined = scan(tmp_path)
    assert examined == 2, examined
    assert violations == {("cyberai/agents/tool.py::fetch", "url", "api.acme.com")}


def test_the_planted_form_is_the_one_the_body_detector_misses(tmp_path: pathlib.Path) -> None:
    """This detector exists only for what the day-40 one cannot see."""
    _plant(tmp_path)
    from_body, resolved = _day40().scan(tmp_path)
    assert resolved == 2, resolved
    assert from_body == set(), from_body
