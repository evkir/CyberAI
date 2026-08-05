"""The SDK import surface used by a normal scan must hold on mcp 1.x and 2.x.

mcp 2.0 renamed streamablehttp_client to streamable_http_client. client_probe
is imported transitively by the CLI at startup, so the rename took down every
scan before recon began -- a target-independent failure that looked like a
dead container.
"""


def test_probe_module_imports():
    from cyberai.mcp import client_probe

    assert client_probe.streamablehttp_client is not None


def test_scan_cli_imports_without_touching_the_mcp_server():
    from cyberai.__main__ import scan

    assert scan is not None


def test_every_sdk_symbol_the_probe_names_resolves():
    from mcp import ClientSession, StdioServerParameters, stdio_client
    from mcp.client.sse import sse_client

    for symbol in (ClientSession, StdioServerParameters, stdio_client, sse_client):
        assert symbol is not None
