"""The coverage page and the agent agree on which stages exist.

docs/redteam/mcp-scanning.md tells a reader what the scan checks. Until this
file existed the table was prose: a stage could be added to run(), or dropped
from it, and the page would go on describing the old set without anything
disagreeing out loud. That is how the agent docstring came to call a
six-stage agent a skeleton for four months.

Both directions, for the same reason the refusal guard states: a stage the
page omits is a check no reader can find, and a stage the page names that
run() no longer calls is a claim about a product that does not do it.

The stages are collected structurally -- the keys run() writes into its
result dict -- rather than from a list kept beside the page. A list would be
a third place to update and would agree with the page by construction
instead of by measurement.

What is not pinned is the Top 25 table's verdicts. Those are a measurement
against an external document, they change when the scanner changes, and a
test that froze them would turn a finding into a chore. What is pinned is
that every verdict is one of the three words the page defines.
"""

import ast
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_AGENT = _ROOT / "cyberai" / "agents" / "mcp_scan" / "agent.py"
_PAGE = _ROOT / "docs" / "redteam" / "mcp-scanning.md"

# Keys of the result dict that carry the probe's own dump rather than the
# output of an analysis stage. The inventory fields reach the result through
# ``**summary`` and never appear as keys of the assigned dict.
_NOT_A_STAGE = frozenset({"probe"})

# How the page spells the stages, against how run() keys them.
_PAGE_NAME = {
    "poisoning": "tool-poisoning",
    "overprivilege": "over-privilege",
    "trust": "trust-propagation",
    "instructions": "server-instructions",
    "attestation": "attestation",
    "exposure": "exposure",
    "auth_metadata": "authorization-metadata",
    "mst": "mst-fuzzing",
}

_FIRST_CELL = re.compile(r"^\|\s*([a-z][a-z0-9-]*)\s*\|", re.MULTILINE)
_VERDICT_CELL = re.compile(r"^\|\s*\d+\s*\|[^|]+\|\s*([a-z]+)\s*\|", re.MULTILINE)
_VERDICTS = frozenset({"yes", "no", "partial"})


def _stages_in_run() -> set[str]:
    """Every analysis stage run() folds into its result, read from the tree."""
    tree = ast.parse(_AGENT.read_text(encoding="utf-8"))
    run = next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    # The dict assigned to ``result``, not any dict in the body: run() also
    # builds the inventory summary and a log payload whose keys are counters.
    # Walking every dict collected those too, which is how the first revision
    # of this guard reported "overprivileged_tools" as a stage.
    assigned = next(
        node.value
        for node in ast.walk(run)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "result"
        and isinstance(node.value, ast.Dict)
    )
    found = {
        key.value
        for key in assigned.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    } - _NOT_A_STAGE
    assert found, "no stages found in run() -- the walker broke"
    return found


def _section(heading: str) -> str:
    lines = _PAGE.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("#")), len(lines))
    return "\n".join(lines[start:end])


def _stages_on_the_page() -> set[str]:
    named = set(_FIRST_CELL.findall(_section("## What it checks")))
    assert named, "the section holds no table"
    return named


def test_every_stage_the_agent_runs_is_on_the_page() -> None:
    expected = {_PAGE_NAME[key] for key in _stages_in_run()}
    missing = expected - _stages_on_the_page()
    assert not missing, f"the agent runs what the page never names: {sorted(missing)}"


def test_the_page_names_no_stage_the_agent_dropped() -> None:
    expected = {_PAGE_NAME[key] for key in _stages_in_run()}
    stale = _stages_on_the_page() - expected
    assert not stale, f"the page names stages run() no longer calls: {sorted(stale)}"


def test_every_top25_row_carries_a_verdict_the_page_defines() -> None:
    section = _section("## Coverage against the MCP Security Top 25")
    verdicts = _VERDICT_CELL.findall(section)
    assert len(verdicts) == 25, f"expected 25 rows, found {len(verdicts)}"
    unknown = set(verdicts) - _VERDICTS
    assert not unknown, f"verdicts the page does not define: {sorted(unknown)}"


def test_the_walker_reads_the_result_and_not_a_list() -> None:
    """Control: the collector answers from code, on input no list would match."""
    sample = ast.parse(
        "def run(self):\n"
        "    self._log('x', {'poisoned_tools': 1})\n"
        "    result: dict = {'poisoning': p, 'invented_stage': x, 'probe': d}\n"
        "    return result\n"
    )
    run = next(n for n in ast.walk(sample) if isinstance(n, ast.FunctionDef))
    assigned = next(
        node.value
        for node in ast.walk(run)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "result"
        and isinstance(node.value, ast.Dict)
    )
    found = {k.value for k in assigned.keys if isinstance(k, ast.Constant)} - _NOT_A_STAGE
    assert found == {"poisoning", "invented_stage"}, found

    everywhere = {
        k.value
        for node in ast.walk(run)
        if isinstance(node, ast.Dict)
        for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    } - _NOT_A_STAGE
    assert found != everywhere, "walking every dict agrees here -- the control is dead"
