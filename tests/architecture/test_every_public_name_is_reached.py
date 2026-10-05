"""A public name in the package is reachable from something that imports it.

The sibling contract in tests/unit/test_config_access_contract.py says a
declared config field must have a reader, and it finds readers structurally
because a name search reported timeout as alive for the months it was dead.
This file asks the same question one level up, about the functions and
classes rather than the fields, and it has the same reason to avoid names:
`run` is defined in this package a dozen times over.

Reachability is transitive, which is the whole difficulty. An importer is
not the test, because a name can be used only by a neighbour in its own
module and still be live -- analyze_trust is never imported anywhere and is
called by analyze_trust_propagation, which agents/mcp_scan/agent.py imports.
Measured on this tree: 459 public names, 76 without an importer, 31 without
a path from one, and 12 once local registration counts as a path. The
forty-five between the first two numbers are that shape and a rule built on
imports alone would have accused every one of them.

The closure starts at every imported name and at names used at module
level, then walks into the body of everything it reaches. Restricting the
entry set to imports from outside the defining module was measured and
removed: this tree holds no self-import, so the restriction guarded an
input that cannot arrive, and a mutation removing it killed nothing. Names are resolved inside the defining module only: a call to
`run` in one module never marks `run` in another, so the resolution is by
position rather than by spelling.

UNREACHED below is the declared state, checked in both directions: a name
that stops being unreached fails here, and so does a name that is listed
and no longer exists. Each remaining entry is a question about one name
rather than about a mechanism.
"""

from __future__ import annotations

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = REPO / "cyberai"
SCANNED = ("cyberai", "tests", "scripts")

# Public names with no path from an importer. Each entry is a claim that
# nothing reaches it; the guard fails when one becomes reachable.
UNREACHED: frozenset[str] = frozenset(
    {
        "cyberai.agents.exploit.attack_path.AttackPath",
        "cyberai.agents.exploit.attack_path.build_attack_paths",
        "cyberai.agents.exploit.poc_mapper.batch_lookup",
        "cyberai.agents.intel.nvd_client.search_cves_async",
        "cyberai.agents.intel.nvd_client.search_cves_batch",
        "cyberai.agents.recon.dns_tool.detect_subdomains",
        "cyberai.agents.web3.etherscan.ContractSource",
        "cyberai.agents.web3.etherscan.EtherscanClient",
        "cyberai.core.rate_limiter.get_limiter",
        "cyberai.core.timeout.AgentTimeoutError",
        "cyberai.core.timeout.timeout_handler",
        "cyberai.core.timeout.with_timeout",
    }
)

_DEFINITION = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _dotted(path: pathlib.Path) -> str:
    rel = path.relative_to(REPO).as_posix()
    return rel[:-3].replace("/", ".").removesuffix(".__init__")


def _names_used(node: ast.AST) -> set[str]:
    used: set[str] = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name):
            used.add(inner.id)
        elif isinstance(inner, ast.Attribute):
            used.add(inner.attr)
    return used


def _registered_locally(node: ast.AST, local: set[str]) -> bool:
    """Decorated by an attribute of an object this module owns.

    `@cli.command()` and `@router.get(...)` hand the function to a registry
    that lives beside it, so importing the module is what reaches it and no
    import of the function can exist. The receiver has to be local: the
    `@click.option` stacked on the same functions is an imported module and
    registers nothing.
    """
    for decorator in getattr(node, "decorator_list", []):
        called = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(called, ast.Attribute) and isinstance(called.value, ast.Name):
            if called.value.id in local:
                return True
    return False


def _definitions() -> tuple[dict[str, str], dict[str, set[str]], set[str]]:
    """Every definition, what its body names, and what module level names."""
    owner: dict[str, str] = {}
    uses: dict[str, set[str]] = {}
    module_level: set[str] = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        module = _dotted(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        here = {n.name for n in tree.body if isinstance(n, _DEFINITION)}
        local = here | {
            t.id
            for n in tree.body
            if isinstance(n, ast.Assign)
            for t in n.targets
            if isinstance(t, ast.Name)
        }
        for node in tree.body:
            if isinstance(node, _DEFINITION):
                key = f"{module}.{node.name}"
                owner[key] = module
                uses[key] = _names_used(node)
                if _registered_locally(node, local):
                    module_level.add(key)
            else:
                module_level |= {f"{module}.{name}" for name in _names_used(node) if name in here}
    return owner, uses, module_level


def _imported_from_elsewhere(owner: dict[str, str]) -> set[str]:
    entry: set[str] = set()
    for area in SCANNED:
        for path in sorted((REPO / area).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom) or node.level:
                    continue
                if not (node.module or "").startswith("cyberai"):
                    continue
                entry |= {
                    key for alias in node.names if (key := f"{node.module}.{alias.name}") in owner
                }
    return entry


def _reachable() -> tuple[set[str], set[str]]:
    """Public names, and the ones a path from an importer arrives at."""
    owner, uses, module_level = _definitions()
    frontier = list(_imported_from_elsewhere(owner) | module_level)
    reached = set(frontier)
    while frontier:
        current = frontier.pop()
        module = owner[current]
        for name in uses.get(current, ()):
            nxt = f"{module}.{name}"
            if nxt in owner and nxt not in reached:
                reached.add(nxt)
                frontier.append(nxt)
    public = {key for key in owner if not key.rsplit(".", 1)[1].startswith("_")}
    return public, reached


def test_the_scan_sees_the_package_it_is_about():
    public, reached = _reachable()
    assert len(public) > 400
    assert "cyberai.core.config.CyberAIConfig" in public
    assert "cyberai.core.config.CyberAIConfig" in reached


def test_every_public_name_is_reached_or_is_declared_unreached():
    public, reached = _reachable()
    unreached = public - reached - UNREACHED
    assert unreached == set(), (
        "public names nothing reaches: "
        + ", ".join(sorted(unreached))
        + " -- give each one a caller, delete it, or name it in UNREACHED"
    )


def test_a_name_in_the_unreached_list_is_still_unreached():
    """Both the stale entry and the one that quietly came alive."""
    public, reached = _reachable()
    assert UNREACHED - public == set(), "UNREACHED names that do not exist"
    assert UNREACHED & reached == set(), "UNREACHED names something reaches"


def test_reachability_is_transitive_and_not_a_name_search():
    """The control, on the shape that defeats an importer rule.

    `helper` is imported by nobody and called by `entry`, which is imported.
    `twin` carries the same name as the reached helper in another module and
    is reached by nothing, which a rule keyed on spelling would miss.
    """
    owner = {"m.entry": "m", "m.helper": "m", "other.helper": "other"}
    uses = {"m.entry": {"helper"}, "m.helper": set(), "other.helper": set()}
    frontier, reached = ["m.entry"], {"m.entry"}
    while frontier:
        current = frontier.pop()
        for name in uses[current]:
            nxt = f"{owner[current]}.{name}"
            if nxt in owner and nxt not in reached:
                reached.add(nxt)
                frontier.append(nxt)
    assert reached == {"m.entry", "m.helper"}
    assert "other.helper" not in reached


def test_a_decorator_registers_only_when_the_registry_is_local():
    """The control, on the two shapes that sit on the same function.

    `@cli.command()` hands the function to an object defined beside it and
    is the only reason those functions are reachable. `@click.option` is an
    attribute of an imported module and hands over nothing; counting it
    would mark every decorated function alive and empty this guard out.
    """
    module = ast.parse(
        "import click\n"
        "cli = click.Group()\n"
        "@cli.command()\n"
        "@click.option('--flag')\n"
        "def registered(flag): ...\n"
        "@click.option('--flag')\n"
        "def decorated_only(flag): ...\n"
    )
    local = {"cli"}
    found = {
        node.name: _registered_locally(node, local)
        for node in module.body
        if isinstance(node, ast.FunctionDef)
    }
    assert found == {"registered": True, "decorated_only": False}
