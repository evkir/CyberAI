"""What the MCP server tells a client must be the version that shipped.

SERVER_VERSION was a literal "0.4.0" while the package was at 1.6.0, so every
handshake -- including the one our own mcp-scan performs and prints -- reported
a number four minor releases stale as fact. The value is published metadata: a
third party auditing our server reads it and has no way to know it is wrong.

The assertion is on the wire, not on the constant. Comparing SERVER_VERSION
with __version__ would pass by construction the moment one is assigned from the
other, and would say nothing about what a client actually receives.
"""

from __future__ import annotations

import asyncio
import sys

from cyberai.mcp.client_probe import probe
from cyberai.version import __version__

LAUNCH = f"{sys.executable} -m cyberai.mcp.server"


def test_the_handshake_reports_the_package_version():
    result = asyncio.run(probe(LAUNCH))

    assert result.error is None, result.error
    assert result.server_name == "cyberai"
    assert result.server_version == __version__, (result.server_version, __version__)
