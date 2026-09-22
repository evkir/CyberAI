"""What kind of assertion holds each closed row of the risk register.

Risk 20 stood closed for fifteen days on a test that read a config field
while an unscoped run spent fifty-one seconds touching a protected range.
The reference resolved, so the existing guard was green and right to be:
it asks whether the named test exists, not what the test asserts.

Two probes on 2026-09-22 established that "measures behaviour" cannot be
decided syntactically. A test calling validate_exploit_scope and checking
its verdict is indistinguishable from one calling from_env and reading
.strict_scope; a rule that fails the second fails the first as well, and
that accusation is false. So this reports rather than judges. The register
declares what holds each row, this measures it, and the guard beside it
fails when the two disagree. A row held by a value read is not forbidden.
It is visible, which is the whole of the fix.

Levels, in the order they are decided:

structural  the test imports nothing from cyberai; it reads the tree,
            a workflow file or a document. Deliberate for some rows.
boundary    something asserts about calls: assert_not_called, call_count,
            call_args. The strongest form available here.
entrypoint  a run-shaped call carries something from cyberai as an
            argument: CliRunner().invoke(cli, ...), asyncio.run(probe()).
            The receiver is the runner, never the product, so the
            argument is what says the product was driven end to end.
            Measured 2026-09-22: this catches the six CLI rows and
            leaves the config reads alone. It does NOT yet catch a run
            on an object a helper built -- rows 7, 13 and 20 read as
            value for that reason. A level below the truth is not a
            false claim, and the guard beside this compares what the
            register declares against what this returns.
value       the product is exercised and the assertions are about values
            it returned or holds.

Helper functions in the same module are followed, because a test whose
body is three calls to module helpers says nothing about itself.
"""

from __future__ import annotations

import ast
import collections
import pathlib
import re
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_REGISTER = _ROOT / "docs" / "architecture" / "risk-register.md"

_ROW = re.compile(r"^\|\s*(\d+)\s*\|(.+?)\|\s*(\w+)\s*\|\s*([\w/-]+)\s*\|(.+)\|\s*$")
_REFERENCE = re.compile(r"tests/[A-Za-z0-9_/]+\.py::[A-Za-z0-9_]+")

_CALL_ASSERTION = re.compile(r"assert_(?:not_)?(?:called|awaited)\w*|call_count|call_args")
_RUN_NAMES = frozenset({"invoke", "run"})

LEVELS = ("structural", "boundary", "entrypoint", "value")


def product_names(tree: ast.Module) -> set[str]:
    """Names this module pulled out of cyberai, under whatever alias."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").startswith("cyberai"):
                names |= {alias.asname or alias.name for alias in node.names}
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("cyberai"):
                    names.add(alias.asname or alias.name.split(".")[0])
    return names


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.value if isinstance(node, (ast.Attribute, ast.Subscript)) else node.func
    return node.id if isinstance(node, ast.Name) else None


def _argument_names(call: ast.Call) -> set[str]:
    """Every name and attribute appearing in the arguments of one call."""
    out: set[str] = set()
    for argument in [*call.args, *(keyword.value for keyword in call.keywords)]:
        for child in ast.walk(argument):
            if isinstance(child, ast.Name):
                out.add(child.id)
            elif isinstance(child, ast.Attribute):
                out.add(child.attr)
    return out


def _mentioned(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            out.add(child.id)
        elif isinstance(child, ast.Attribute):
            out.add(child.attr)
    return out


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def level_of(source: str, function: str) -> str:
    """The level of one test, following helpers defined in the same module."""
    tree = ast.parse(source)
    product = product_names(tree)
    functions = _functions(tree)
    if function not in functions:
        return "structural"

    seen: set[str] = set()
    queue: collections.deque[str] = collections.deque([function])
    reaches = False
    boundary = False
    entrypoint = False

    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        node = functions.get(current)
        if node is None:
            continue
        segment = ast.get_source_segment(source, node) or ""
        if _CALL_ASSERTION.search(segment):
            boundary = True
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            if isinstance(call.func, ast.Name):
                called = call.func.id
            elif isinstance(call.func, ast.Attribute):
                called = call.func.attr
                root = _root_name(call.func.value)
                if root is not None and root in product:
                    reaches = True
            else:
                continue
            if called in product:
                reaches = True
            if called in _RUN_NAMES and _argument_names(call) & product:
                entrypoint = True
                reaches = True
        if product & _mentioned(node):
            reaches = True
        for name in _mentioned(node):
            if name in functions and name not in seen:
                queue.append(name)

    if not reaches:
        return "structural"
    if boundary:
        return "boundary"
    if entrypoint:
        return "entrypoint"
    return "value"


def closed_references(text: str) -> list[tuple[int, str]]:
    """(row number, node id) for every reference a closed row carries."""
    out: list[tuple[int, str]] = []
    for line in text.splitlines():
        match = _ROW.match(line)
        if match and match.group(3) == "closed":
            for reference in _REFERENCE.findall(match.group(5)):
                out.append((int(match.group(1)), reference))
    return out


def rows(text: str) -> list[tuple[int, str, str]]:
    """(number, status, declared level) for each numbered row."""
    out: list[tuple[int, str, str]] = []
    for line in text.splitlines():
        match = _ROW.match(line)
        if match:
            out.append((int(match.group(1)), match.group(3), match.group(4)))
    return out


def declared_level(text: str, number: int) -> str:
    """What the page says holds one row, or the empty string if it says nothing."""
    for found, _, level in rows(text):
        if found == number:
            return level
    return ""


def measure(root: pathlib.Path, text: str) -> list[tuple[int, str, str]]:
    """(row, reference, level) for every closed reference in the register."""
    out: list[tuple[int, str, str]] = []
    for number, reference in closed_references(text):
        relative, _, function = reference.partition("::")
        path = root / relative
        if not path.exists():
            out.append((number, reference, "structural"))
            continue
        out.append((number, reference, level_of(path.read_text(encoding="utf-8"), function)))
    return out


def main() -> int:
    measured = measure(_ROOT, _REGISTER.read_text(encoding="utf-8"))
    counts: collections.Counter[str] = collections.Counter(level for _, _, level in measured)
    for number, reference, level in measured:
        print(f"{number:>3}  {level:<11} {reference}")
    print()
    print("  ".join(f"{level}: {counts[level]}" for level in LEVELS))
    print(f"references: {len(measured)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
