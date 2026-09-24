"""The declared-field access contract from cyberai/core/config.py, enforced.

Every field on CyberAIConfig exists on every instance, so a getattr fallback
over one of those names is dead code that hides a rename behind a default.
This scans the shipped package rather than a fixture: a new call site anywhere
in cyberai/ has to satisfy the contract without anyone remembering this file.

The second contract here is that a declared field has somebody who reads it.
Four did not: intel, timeout, verbose and use_lab_dogfood. Each was a lever
in the config, in the CLI or on a documentation page, and none of them moved
anything -- the switch that gated the lab dashboard gated nothing, the -v
flag turned on output the package cannot produce, and two were inert from
the commit that introduced them. Tests kept all four green by asserting the
value travels from the environment into the object, which is true of any
field and says nothing about whether the run consults it.

A field with no reader is allowed only when it says so. EXTENSION_POINTS
below is that declaration: a name in it is a field kept deliberately ahead
of its consumer, and the list is short enough to argue with in review. An
empty list is the honest state today and the guard reads correctly when it
is empty.

Readers are found structurally, by attribute access on something named like
a config, not by looking for the field name in the file. The difference is
not cosmetic: timeout appears thirty-three times in the package, every one
of them an attribute of a tool or a client, and a name-based rule would
have reported it as alive for as long as it was dead.
"""

import ast
import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "cyberai"
CONFIG = PACKAGE / "core" / "config.py"

# Fields deliberately kept ahead of a consumer. A name here is a claim that
# somebody intends to read it; an empty list is the state this file was
# written in.
EXTENSION_POINTS: frozenset[str] = frozenset()

# Owners that stand for a CyberAIConfig: config, cfg, self.config, and the
# app-state spelling the web routes use.
_CONFIGISH = re.compile(r"(^|\.)(config|cfg|conf)$")


def _declared_fields() -> set[str]:
    tree = ast.parse(CONFIG.read_text())
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "CyberAIConfig":
            return {
                st.target.id
                for st in node.body
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)
            }
    raise AssertionError("CyberAIConfig is not declared in core/config.py")


def _getattr_calls_on_declared_fields() -> list[str]:
    declared = _declared_fields()
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
                continue
            if len(node.args) < 2 or not isinstance(node.args[1], ast.Constant):
                continue
            name = node.args[1].value
            if isinstance(name, str) and name in declared:
                rel = path.relative_to(PACKAGE.parent)
                offenders.append(f"{rel}:{node.lineno} {ast.unparse(node)}")
    return offenders


def test_the_config_declares_the_fields_this_contract_is_about():
    declared = _declared_fields()
    assert "use_oob" in declared
    assert "max_agent_iterations" in declared
    assert len(declared) > 20


def test_no_declared_config_field_is_read_through_getattr():
    offenders = _getattr_calls_on_declared_fields()
    assert offenders == [], "declared fields read through getattr:\n" + "\n".join(offenders)


def test_the_scan_still_walks_the_package():
    scanned = sorted(PACKAGE.rglob("*.py"))
    assert len(scanned) > 50
    assert CONFIG in scanned


def _fields_read_in(tree: ast.AST, declared: set[str]) -> set[str]:
    """Field names this tree reads off something that stands for a config."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or isinstance(node.ctx, ast.Store):
            continue
        if node.attr not in declared:
            continue
        if _CONFIGISH.search(ast.unparse(node.value)):
            found.add(node.attr)
    return found


def _readers_in_package() -> set[str]:
    declared = _declared_fields()
    read: set[str] = set()
    for path in sorted(PACKAGE.rglob("*.py")):
        if path == CONFIG:
            continue
        read |= _fields_read_in(ast.parse(path.read_text()), declared)
    return read


def test_every_declared_field_has_a_reader_or_says_it_has_none():
    declared = _declared_fields()
    unread = declared - _readers_in_package() - EXTENSION_POINTS
    assert unread == set(), (
        "fields no module reads off a config: "
        + ", ".join(sorted(unread))
        + " -- give each one a reader, delete it, or name it in EXTENSION_POINTS"
    )


def test_a_name_in_the_extension_list_is_a_field_that_exists():
    """A stale entry would excuse a field that is already gone."""
    ghosts = EXTENSION_POINTS - _declared_fields()
    assert ghosts == set(), f"EXTENSION_POINTS names fields that do not exist: {sorted(ghosts)}"


def test_the_reader_rule_is_about_access_not_about_the_name():
    """The control, on input where a name search and this rule disagree.

    Both samples mention the field name. Only the first reads it off a
    config, and a rule that searched for the text would call both alive --
    which is exactly how timeout stayed declared dead for months while
    thirty-three unrelated .timeout attributes sat in the tree.
    """
    declared = {"max_rps"}
    reads = ast.parse("limit = self.config.max_rps\n")
    mentions = ast.parse("limit = self.scanner.max_rps\nmax_rps = 5\n")
    assert _fields_read_in(reads, declared) == {"max_rps"}
    assert _fields_read_in(mentions, declared) == set()

    # Writing a field is not reading it. This is the shape the -v flag had:
    # the CLI assigned config.verbose on every run and no module ever asked
    # for it, so counting the assignment would have reported the dead switch
    # as a live one.
    writes = ast.parse("config.max_rps = 5\n")
    assert _fields_read_in(writes, declared) == set()
