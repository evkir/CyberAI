"""Every stage handed the probed tool list is also handed why it may be empty.

The surface the probe returns is empty in three cases and only one of them is
an answer. `run` reads the reason off `surface_errors` and passes it to each
stage that scores the list, so a stage reports an unmeasured surface rather
than a clean one. Nothing structural stops the next stage from being wired
without it: the call still type-checks, the suite still passes, and the defect
is a verdict about a surface nobody read -- which is exactly how the five
existing consumers acquired it.

So the rule is on the call site. A stage call in `run` that takes
`probe_result["tools"]` must also take the unread reason, with one exception
planted below as a control: `_analyze_instructions` is deliberately not given
it, because its summons rule reads an empty advertised set correctly through
sentence scope and gating it on a non-empty list was priced and rejected in
instructions.py. The exception is named here rather than left to the reader,
so adding a second one is a decision someone makes on purpose.

What this does not cover, measured rather than assumed: the walk recognises a
stage call by the literal subscript `probe_result["tools"]` in its arguments,
so a list bound to a local first is invisible to it. The floor below fails if
the walk stops finding the calls that do, which is the failure mode that
matters -- a walk finding nothing reports no violation and looks clean.
"""

from __future__ import annotations

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_AGENT = _ROOT / "cyberai" / "agents" / "mcp_scan" / "agent.py"

# The reason, as `run` binds it before the stage calls.
_UNREAD = "tools_unread"

# Scored through sentence scope, which reads an empty advertised set correctly.
_EXEMPT = frozenset({"_analyze_instructions"})

# `len` is not a stage: the summary counts the list rather than scoring it, and
# carries the reason beside the count as `surface_errors`. That pairing is
# asserted on its own below, so the count cannot quietly lose it either.
_NOT_A_STAGE = frozenset({"len"})

# Five stage calls in `run` are handed the list: poisoning, over-privilege,
# exposure, trust, and the exempt instructions. The exemption is applied after
# counting, so the floor counts what the walk sees rather than what the rule
# judges -- a walk that stops seeing the exempt call is just as broken.
# Measured, not reasoned: the first value written here was 4.
_STAGE_CALL_FLOOR = 5


def _reads_the_tool_list(node: ast.Call) -> bool:
    """Whether this call is handed `probe_result["tools"]` directly."""
    for arg in node.args + [kw.value for kw in node.keywords]:
        if (
            isinstance(arg, ast.Subscript)
            and isinstance(arg.value, ast.Name)
            and arg.value.id == "probe_result"
            and isinstance(arg.slice, ast.Constant)
            and arg.slice.value == "tools"
        ):
            return True
    return False


def _name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return "?"


def scan(path: pathlib.Path) -> tuple[set[str], int]:
    """Stage calls reading the tool list without the reason, and calls seen."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    violations: set[str] = set()
    seen = 0
    for fn in ast.walk(tree):
        if not (isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name == "run"):
            continue
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and _reads_the_tool_list(node)):
                continue
            name = _name(node)
            if name in _NOT_A_STAGE:
                continue
            seen += 1
            if name in _EXEMPT:
                continue
            passed = {ast.unparse(a) for a in node.args} | {
                ast.unparse(kw.value) for kw in node.keywords
            }
            if _UNREAD not in passed:
                violations.add(name)
    return violations, seen


def test_every_stage_scoring_the_list_is_told_when_it_was_not_read() -> None:
    violations, _ = scan(_AGENT)
    assert violations == set(), (
        "these stages score the probed tool list without being told the read "
        "may have failed, so an empty list reads to them as a server with "
        "nothing to find: " + repr(sorted(violations))
    )


def test_the_walk_still_finds_the_stage_calls() -> None:
    """A walk that finds nothing reports no violation and looks clean."""
    _, seen = scan(_AGENT)
    assert seen >= _STAGE_CALL_FLOOR, (
        f"only {seen} stage calls read the tool list; the walk is broken, not the agent"
    )


def test_the_instructions_exemption_is_still_the_only_one() -> None:
    """The exemption is a decision, so a second one is made on purpose."""
    assert _EXEMPT == {"_analyze_instructions"}


def test_the_counted_list_carries_its_reason_in_the_summary() -> None:
    """The one non-stage reader: the count travels with `surface_errors`.

    `len` is skipped by the rule above because counting a list is not scoring
    it. That skip is only safe while the summary holding the count also holds
    the reason, which is what this asserts -- otherwise a reader of the count
    is back to reading zero as a measurement.
    """
    tree = ast.parse(_AGENT.read_text(encoding="utf-8"))
    summaries = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        and any(
            isinstance(k, ast.Constant) and k.value == "tools" for k in node.keys if k is not None
        )
        and any(
            isinstance(v, ast.Call) and _name(v) == "len" and _reads_the_tool_list(v)
            for v in node.values
        )
    ]
    assert summaries, "no summary counts the probed tool list; the walk is broken"
    for summary in summaries:
        keys = {k.value for k in summary.keys if isinstance(k, ast.Constant)}
        assert "surface_errors" in keys, (
            "a summary counting the tool list without the reason the count may "
            "be zero: " + ast.unparse(summary)[:120]
        )


def test_the_floor_is_a_measurement_not_a_formality() -> None:
    """A floor of zero passes on a broken walk, which is the failure it guards.

    Mutating `_STAGE_CALL_FLOOR` to 0 left the suite green: the floor test
    asserts `seen >= floor`, so lowering the floor disables it silently. The
    count is therefore pinned to what the agent actually contains.
    """
    _violations, seen = scan(_AGENT)
    assert _STAGE_CALL_FLOOR > 0, "a floor of zero cannot detect a broken walk"
    assert seen == _STAGE_CALL_FLOOR, (
        f"the agent has {seen} stage calls reading the tool list and the floor "
        f"says {_STAGE_CALL_FLOOR}; whichever changed, both must say the same"
    )


def test_a_planted_stage_without_the_reason_is_caught(tmp_path: pathlib.Path) -> None:
    """The rule is measured against known-bad input, not trusted on silence.

    The exempt call is the control: a rule that forgot the exemption flags it.
    """
    planted = tmp_path / "agent.py"
    planted.write_text(
        "class A:\n"
        "    def run(self, target):\n"
        "        probe_result = self.call_tool('mcp_probe')\n"
        "        tools_unread = (probe_result.get('surface_errors') or {}).get('tools')\n"
        "        a = self._analyze_poisoning(target, probe_result['tools'], tools_unread)\n"
        "        b = self._analyze_trust(target, probe_result['tools'])\n"
        "        c = self._analyze_instructions(target, None, probe_result['tools'])\n"
        "        return a, b, c\n",
        encoding="utf-8",
    )
    violations, seen = scan(planted)
    assert seen == 3, seen  # len() in the planted source would not be counted
    assert violations == {"_analyze_trust"}, sorted(violations)
