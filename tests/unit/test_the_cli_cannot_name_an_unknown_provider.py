"""--provider is answered by the parser, not by the run.

The CLI assigned its string straight onto config.llm.provider, a field
declared Literal, so `--provider gemini` produced a config naming a provider
that does not exist. __main__.py was outside [tool.mypy] files, so the
assignment was invisible to CI as well.

The environment reader narrows silently, because a scan must not die of a
stale variable in a .env file. A flag is the opposite case: it was typed just
now, by someone at a terminal who can read the answer and retype it, so the
parser rejects it and names the set. Two boundaries, two behaviours, one
declared list behind both.
"""

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.core.config import _PROVIDERS


def test_an_unknown_provider_is_refused_by_the_parser():
    result = CliRunner().invoke(cli, ["scan", "example.com", "--provider", "gemini"])
    assert result.exit_code == 2
    assert "gemini" in result.output


def test_the_refusal_names_the_providers_that_exist():
    """A rejection that does not say what is accepted costs another round trip."""
    result = CliRunner().invoke(cli, ["scan", "example.com", "--provider", "gemini"])
    for name in _PROVIDERS:
        assert name in result.output


def test_the_declared_providers_are_offered_by_the_help():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    for name in _PROVIDERS:
        assert name in result.output
