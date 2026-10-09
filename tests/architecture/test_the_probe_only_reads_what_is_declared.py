"""The README says the MCP scan does not call a target's tools. This holds it.

The headline used to claim runtime testing for MCP servers while the probe
sent `initialize` and three `list_*` calls and nothing else. Nothing caught
it, because every gate over the headline checked that a named module exists,
and `cyberai/agents/mcp_scan/agent.py` does exist. Existence is not
behaviour, and the claim was about behaviour.

The claim now reads the other way -- it names a thing the scanner does NOT
do -- and a negative claim decays silently: the day someone adds a tool call
to the probe, the README becomes false in the opposite direction and no test
notices. So the boundary itself is asserted here.

Method calls are read off the AST rather than grepped, because `call_tool`
names three unrelated things in this tree: the agent-side tool registry
(`core/base_agent.py`), the handler our own server exposes
(`mcp/server.py`), and the SDK session method that would reach a target.
Only the third one bears on the claim, and only the AST can tell them apart.

The allowed set is the read surface: initialize plus the three inventory
calls. Anything else on a session reaches out and touches the target, which
is the line the README draws and the legal framing of the sprint depends on.
"""

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PRODUCTION = _ROOT / "cyberai"
_PROBE = _PRODUCTION / "mcp" / "client_probe.py"

# What a session is allowed to be asked for: the declared surface, nothing
# that executes on the target's side.
_READ_ONLY = {"initialize", "list_tools", "list_prompts", "list_resources"}

# The name the probe binds its session to, and the parameter `inventory`
# receives it as.
_SESSION_NAMES = {"session"}


def _session_methods(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        value = node.value
        if isinstance(value, ast.Name) and value.id in _SESSION_NAMES:
            found.add(node.attr)
    return found


def test_the_probe_asks_the_target_only_for_what_it_declares() -> None:
    reached = _session_methods(_PROBE)
    beyond = sorted(reached - _READ_ONLY)
    assert not beyond, (
        f"the probe calls {beyond} on a target session. The README states it "
        "does not call a target's tools; change the claim or drop the call."
    )


def test_the_scan_sees_the_calls_it_is_meant_to_police() -> None:
    """A gate over an empty set passes and measures nothing."""
    reached = _session_methods(_PROBE)
    assert _READ_ONLY <= reached, sorted(_READ_ONLY - reached)


def test_only_the_probe_opens_a_session_to_a_target() -> None:
    """A second door would route around the check above."""
    openers = sorted(
        str(path.relative_to(_ROOT))
        for path in _PRODUCTION.rglob("*.py")
        if "ClientSession" in path.read_text(encoding="utf-8")
    )
    assert openers == ["cyberai/mcp/client_probe.py"], openers
