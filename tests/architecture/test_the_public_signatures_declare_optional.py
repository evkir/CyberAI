"""A public argument that accepts None must say so.

validate_exploit_scope declared `authorized_scope: List[str] = None` and
`attack_paths: List[Dict[str, Any]] = None`. PEP 484 prohibits the implicit
Optional, and mypy has defaulted to rejecting it for years, so the two lines
were two errors for every importer -- and the module sat outside
[tool.mypy] files, so nobody was shown them. The body reads both through a
falsiness check, so None was always accepted; only the declaration said
otherwise.

The rule is stated over the signature rather than over a call, because a
call cannot fail on a default it does not pass. A test that called with None
and got a result would have passed before this commit too.
"""

import inspect
import typing

from cyberai.agents.exploit.safety_validator import validate_exploit_scope


def _accepts_none(annotation: object) -> bool:
    return type(None) in typing.get_args(annotation)


def test_every_none_defaulted_argument_is_declared_optional():
    hints = typing.get_type_hints(validate_exploit_scope)
    offenders = [
        name
        for name, param in inspect.signature(validate_exploit_scope).parameters.items()
        if param.default is None and not _accepts_none(hints[name])
    ]
    assert not offenders, f"None default on a non-Optional annotation: {offenders}"


def test_the_rule_is_not_vacuous():
    """Control: the check above is worthless if no argument defaults to None."""
    defaults = [
        name
        for name, param in inspect.signature(validate_exploit_scope).parameters.items()
        if param.default is None
    ]
    assert sorted(defaults) == ["attack_paths", "authorized_scope"]


def test_none_is_accepted_where_the_signature_says_it_is():
    """The declaration and the body must agree in the direction that matters."""
    result = validate_exploit_scope("93.184.216.34", None, None)
    assert result.passed is True
    assert any("No authorized_scope" in w for w in result.warnings)
