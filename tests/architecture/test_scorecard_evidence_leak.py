"""Target output recorded in a finding must not reach the published card.

Tail CH. A confirmed finding carries `evidence`: the target's own response,
verbatim. Against our bench that response contains the flag the target plants,
which is legitimate -- it is the target speaking, not a constant of ours -- but
it means the string travels in `details["findings"]`, and `details` is the
input the scorecard is rendered from.

Today it does not arrive: the renderer reads six keys and `findings` is not
one of them. That is a property of the current code, not a decision anyone
recorded, so a column added tomorrow would carry our own targets' text into
the artefact we publish as evidence of honesty -- and it would do so silently,
with every existing test green.

Two assertions, because either alone is weak. The behavioural one renders a
card from a finding holding a planted secret and requires the secret to be
absent; it would survive a new column that happens not to print evidence. The
structural one pins the exact set of keys the renderer reads, so any new
column is a decision someone has to make on purpose.

The secret is read from the bench app rather than written here: a hard-coded
copy keeps passing on the day the app changes what it plants.
"""

import ast
import pathlib

import pytest

from cyberai.bench import scorecard
from cyberai.bench.apps import path_traversal
from cyberai.bench.runner import BenchResult, SuiteReport
from cyberai.bench.scorecard import generate_scorecard

REPO = pathlib.Path(__file__).resolve().parents[2]
SCORECARD = REPO / "cyberai" / "bench" / "scorecard.py"
AGENT_ENGINE = REPO / "cyberai" / "bench" / "agent_engine.py"
CVE_RUNNER = REPO / "cyberai" / "bench" / "cve_bench_runner.py"

# What the renderer is allowed to read out of a task's details. Every entry is
# a number or a class name. None of them is text the target wrote.
DECLARED_KEYS = frozenset(
    {
        "vuln_class",
        "available",
        "endpoints_tested",
        "agent_confirmed",
        "oob_confirmed",
        "requests_sent",
    }
)


def _details_keys_read_by_the_scorecard() -> set[str]:
    """Every details key the renderer reads, by reading the renderer.

    Constant subscripts and membership tests come from the syntax tree;
    the metric columns are looked up through a variable, so they come from
    the table itself.
    """
    tree = ast.parse(SCORECARD.read_text(encoding="utf-8"))
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and "details" in ast.unparse(func.value)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.add(node.args[0].value)
        elif isinstance(node, ast.Compare):
            if (
                len(node.ops) == 1
                and isinstance(node.ops[0], ast.In)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and "details" in ast.unparse(node.comparators[0])
            ):
                keys.add(node.left.value)
    keys.update(key for key, _ in scorecard._METRIC_COLUMNS)
    return keys


def _report_carrying_a_planted_secret() -> tuple[SuiteReport, str]:
    """One solved task whose finding quotes what the bench target plants."""
    secret = path_traversal.SECRET_BODY.strip()
    finding = {
        "vuln_class": "path_traversal",
        "parameter": "file",
        "proof": "reads a file outside the web root",
        "evidence": secret,
    }
    results = (
        BenchResult(
            "local-path-traversal",
            "local",
            True,
            1.0,
            details={
                "engine": "agent",
                "vuln_class": "path_traversal",
                "available": True,
                "agent_confirmed": 1,
                "oob_confirmed": 0,
                "endpoints_tested": 1,
                "requests_sent": 3,
                "findings": [finding],
            },
        ),
    )
    return SuiteReport(suite="local", total=1, solved=1, results=results), secret


@pytest.mark.architecture
def test_target_output_recorded_in_a_finding_does_not_reach_the_card():
    report, secret = _report_carrying_a_planted_secret()

    md = generate_scorecard(report)

    assert secret not in md, (
        "the card quotes what our own target plants. It is the target's text, "
        "not ours, but a scorecard repeating it cannot be read as independent "
        "evidence of anything."
    )


@pytest.mark.architecture
def test_the_scorecard_reads_only_the_keys_it_declares():
    read = _details_keys_read_by_the_scorecard()

    assert read == set(DECLARED_KEYS), (
        f"the renderer now reads {sorted(read - set(DECLARED_KEYS))} and no "
        f"longer reads {sorted(set(DECLARED_KEYS) - read)}. Adding a column is "
        "allowed; adding one that carries target output into the artefact is "
        "the thing this file exists to make deliberate."
    )


@pytest.mark.architecture
def test_the_rule_is_not_vacuous():
    """A guard over an empty set passes forever.

    Three ways this could quietly stop guarding: the syntax scan finding
    nothing, the bench planting no secret, or the runners no longer putting
    findings into details at all -- at which point there is no leak to guard
    against and this file should be deleted rather than left green.
    """
    assert len(_details_keys_read_by_the_scorecard()) >= 4, "renderer not being scanned"
    assert path_traversal.SECRET_BODY.strip(), "the bench plants nothing to leak"
    for path in (AGENT_ENGINE, CVE_RUNNER):
        assert '"findings": outcome.findings' in path.read_text(encoding="utf-8"), (
            f"{path.name} no longer publishes findings into details"
        )
