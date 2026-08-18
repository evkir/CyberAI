"""The declared-field access contract from cyberai/core/config.py, enforced.

Every field on CyberAIConfig exists on every instance, so a getattr fallback
over one of those names is dead code that hides a rename behind a default.
This scans the shipped package rather than a fixture: a new call site anywhere
in cyberai/ has to satisfy the contract without anyone remembering this file.
"""

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2] / "cyberai"
CONFIG = PACKAGE / "core" / "config.py"


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
