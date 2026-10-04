"""A parameter's annotation is a claim about its callers, and this one was false.

AuditLogger declared ``output_dir: str`` and defaulted it to the string
``"reports/"``. Every production call site that supplies it passes
``config.output_dir``, which CyberAIConfig annotates as ``Path``. Nothing broke,
because the value was only ever interpolated into an f-string and a Path
interpolates as its own text -- so the declaration was wrong in a way no run
could report and no test could see. The file is outside the mypy scope, which is
why the checker did not say so either.

This file is the instrument that says so. It reads the annotation and the call
sites from the tree rather than from memory, and compares them with the same
key, so the day someone narrows the parameter back the divergence is named
rather than tolerated for another month.

The behaviour is asserted too, but only for what the assertion can see. Joining
with Path instead of interpolating removes a doubled separator against the old
trailing-slash default, and that repair is not observable: reverting the join by
itself reds nothing here, because logging normalises the path it is handed. It
was checked by mutation rather than assumed. What the last test does pin is that
the production type produces the documented file name.
"""

import ast
import dataclasses
import inspect
import pathlib
import re
import typing

from cyberai.core.config import CyberAIConfig
from cyberai.core.logger import AuditLogger

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_CONFIGISH = re.compile(r"(?i).*(config|cfg|conf)$")
_PACKAGE = _ROOT / "cyberai"


def _sites_supplying_the_directory() -> list[tuple[str, str]]:
    """Every construction of an AuditLogger in the package that names output_dir."""
    found = []
    for module in sorted(_PACKAGE.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "id", None) != "AuditLogger":
                continue
            for keyword in node.keywords:
                if keyword.arg == "output_dir":
                    found.append((module.relative_to(_ROOT).as_posix(), ast.unparse(keyword.value)))
    return found


def test_the_directory_is_supplied_from_one_place_in_the_package() -> None:
    """Every call site reads the attribute off a config, so there is one source to match.

    The assertion was written against the literal expression ``config.output_dir``
    and held while every caller happened to name its variable ``config``. The
    bench path receives the config as a parameter that may be None and resolves
    it into ``cfg``, which is the same object reached by the same attribute. The
    claim worth holding is that the directory comes off a config rather than from
    a literal or a computed path, so it is asserted on the attribute and on the
    shape of the owner, not on the spelling of a local name.

    The owner is matched the way test_config_access_contract matches one, which
    is where that predicate already lives in this tree.
    """
    sites = _sites_supplying_the_directory()
    assert sites, "no call site names output_dir at all"
    off_a_config = {
        expression
        for _, expression in sites
        if _CONFIGISH.fullmatch(expression.rsplit(".", 1)[0] if "." in expression else "")
        and expression.endswith(".output_dir")
    }
    assert off_a_config == {expression for _, expression in sites}, sites


def test_the_declaration_admits_the_type_its_callers_pass() -> None:
    """The claim the parameter makes has to cover the value that reaches it."""
    passed = typing.get_type_hints(CyberAIConfig)["output_dir"]
    declared = typing.get_type_hints(AuditLogger.__init__)["output_dir"]
    admitted = set(typing.get_args(declared)) or {declared}
    assert passed in admitted, (
        f"AuditLogger declares output_dir as {declared}, and its callers pass "
        f"CyberAIConfig.output_dir which is {passed}"
    )


def test_the_default_directory_is_the_one_the_config_would_have_given() -> None:
    """Three call sites omit it, so the default is a production path, not a placeholder."""
    default = inspect.signature(AuditLogger.__init__).parameters["output_dir"].default
    field = next(f for f in dataclasses.fields(CyberAIConfig) if f.name == "output_dir")
    assert pathlib.Path(default) == field.default, (default, field.default)


def test_the_trail_lands_where_the_directory_says(tmp_path: pathlib.Path) -> None:
    """Passing the production type has to produce the documented file name."""
    AuditLogger(session_id="d35", output_dir=tmp_path)
    assert (tmp_path / "audit_d35.jsonl").exists(), sorted(p.name for p in tmp_path.iterdir())
