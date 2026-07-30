"""The CLI reports its version, and reports the one the package declares."""

from __future__ import annotations

from click.testing import CliRunner

from cyberai.__main__ import cli
from cyberai.version import __version__


def test_version_option_prints_the_package_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    # A hardcoded string here would pass a bump it never followed.
    assert __version__ in result.output


def test_short_version_flag_works():
    assert CliRunner().invoke(cli, ["-V"]).exit_code == 0
