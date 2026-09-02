"""No production proof may carry knowledge of our own benchmark targets.

W2-D1.4. C3 in STANDOFF-KEY is the shape this guards against, and the shape
turned out to be wider than the plan described. The obvious form was a flag
string: a module constant in the exploitation engine held the exact flag
cyberai/bench/apps/path_traversal.py plants outside its web root, and shipped
to PyPI with it. The constant is not repeated here -- a rule against a literal
that quotes the literal spreads what it forbids. The second form carried no
flag at all --
the SQLi proof looked for `"status": "ok"`, which is what our bench login
prints and also what Juice Shop returns from an untouched product listing.

So this file asserts two different things. The first is textual and narrow:
no flag literal outside the bench package. The second is behavioural: run
every production proof against every string the bench targets are built from,
and require that none of them is satisfied. A grep cannot do the second, and
the second is what actually caught the harder case.

Known limitation, stated rather than hidden: a differential proof answers
False without a ProofContext by construction, so the behavioural check cannot
inspect one. Supplying a synthetic context would make every literal confirm
and the check would report noise instead of contamination. Differential proofs
are covered by their own unit tests, which drive real transitions.
"""

import ast
import pathlib
import re

from cyberai.agents.exploit.web_payloads import Proof, WebPayload, WebVulnClass, full_corpus
from cyberai.bench.apps import path_traversal

REPO = pathlib.Path(__file__).resolve().parents[2]
PRODUCTION = REPO / "cyberai"
BENCH = PRODUCTION / "bench"
BENCH_APPS = BENCH / "apps"

_FLAG_LITERAL = re.compile(r"FLAG\{")


def _production_modules() -> list[pathlib.Path]:
    """Everything shipped except the benchmark package itself.

    The bench is where target knowledge belongs: its evaluator is supposed to
    know what its own apps plant. The engine is not.
    """
    return [p for p in sorted(PRODUCTION.rglob("*.py")) if not p.is_relative_to(BENCH)]


def _bench_target_literals() -> list[tuple[str, int, str]]:
    """Every non-blank string constant the bench targets are built from."""
    out: list[tuple[str, int, str]] = []
    for path in sorted(BENCH_APPS.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.strip():
                    out.append((path.name, node.lineno, node.value))
    return out


def _confirmations(payloads: list[WebPayload]) -> list[str]:
    violations: list[str] = []
    for payload in payloads:
        for name, line, literal in _bench_target_literals():
            if payload.proof.holds(literal):
                violations.append(
                    f"{payload.vuln_class.value}: {payload.value!r} is confirmed by "
                    f"{name}:{line} {literal[:60]!r}"
                )
    return violations


def test_no_bench_flag_literal_reaches_the_production_engine():
    offenders = [
        str(p.relative_to(REPO))
        for p in _production_modules()
        if _FLAG_LITERAL.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        f"benchmark flag literals outside cyberai/bench/: {offenders}. "
        "A proof that recognises a string this project plants measures "
        "recognition, not exploitation, and ships that string to every user."
    )


def test_no_production_proof_is_satisfied_by_a_bench_target_literal():
    violations = _confirmations(full_corpus())
    assert not violations, "proofs confirmed by our own targets' text: " + "; ".join(violations)


def test_the_rule_is_not_vacuous():
    """A check that scans nothing passes forever.

    Both halves have a way of quietly measuring an empty set: a path typo
    leaves no modules to read, and a bench package that stopped defining
    string constants leaves nothing to compare against.
    """
    assert len(_production_modules()) > 100, "production modules not being scanned"
    assert len(_bench_target_literals()) > 20, "bench target literals not being read"
    assert full_corpus(), "no payloads to check"
    planted = [v for _, _, v in _bench_target_literals() if _FLAG_LITERAL.search(v)]
    assert planted, "the bench no longer plants a flag; this rule now guards nothing"


def test_the_rule_catches_a_contaminated_proof():
    """The guard must fire, not merely pass on a clean corpus.

    The literal comes from the bench app rather than from this file: a
    hard-coded copy would keep passing on the day the app changed its secret,
    which is the drift tests/unit/test_bench_app_contract.py exists to catch
    on the other side of the same seam.
    """
    contaminated = WebPayload(
        vuln_class=WebVulnClass.PATH_TRAVERSAL,
        value="../../../../etc/somewhere",
        proof=Proof(
            description="reads the file our own bench planted",
            expected=path_traversal.SECRET_BODY.strip(),
        ),
    )
    assert _confirmations([contaminated])
