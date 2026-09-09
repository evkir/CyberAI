"""The HTTP transport must reach the network, and say so when it cannot.

``_open_streams`` unpacked the streamable-HTTP context manager into exactly
three names. mcp 2.x yields two, so every HTTP scan died inside the client
with a ValueError before a packet was sent -- and the task group wrapping
every transport reported it as "ExceptionGroup: unhandled errors in a
TaskGroup (1 sub-exception)", which is indistinguishable from a refused
connection, a TLS failure or a 401. The suite was green because no test had
ever driven the HTTP branch.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import pytest

from cyberai.mcp import client_probe
from cyberai.mcp.client_probe import _describe, _open_streams, probe


def _closed_port() -> int:
    """A port nothing is listening on: bound to learn the number, then released."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _read_write(streams) -> tuple[object, object]:
    async def _run():
        async with streams as pair:
            return pair

    return asyncio.run(_run())


def _fake_client(count: int):
    """Stand in for the SDK transport, yielding the arity a release shipped."""

    @asynccontextmanager
    async def _client(endpoint: str):
        yield tuple(f"stream{i}" for i in range(count))

    return _client


def test_the_http_branch_reaches_the_network_not_a_client_side_error():
    """Before the fix this failed inside the client, never touching the socket."""
    result = asyncio.run(probe(f"http://127.0.0.1:{_closed_port()}/mcp"))

    assert result.connected is False
    assert result.error is not None
    assert "unpack" not in result.error, result.error
    assert "Connect" in result.error, result.error


def test_the_error_names_the_cause_and_not_the_task_group():
    result = asyncio.run(probe(f"http://127.0.0.1:{_closed_port()}/mcp"))

    assert "ExceptionGroup" not in (result.error or ""), result.error


@pytest.mark.parametrize("count", [2, 3])
def test_the_http_transport_survives_either_arity_the_sdk_has_shipped(monkeypatch, count):
    """mcp 1.x yielded three, 2.x yields two, and the third was never used."""
    monkeypatch.setattr(client_probe, "streamablehttp_client", _fake_client(count))

    read, write = _read_write(_open_streams("http://target/mcp", "http"))

    assert (read, write) == ("stream0", "stream1")


def test_a_task_group_failure_is_described_by_its_leaves():
    group = BaseExceptionGroup("outer", [ValueError("bad shape"), OSError("refused")])

    assert _describe(group) == "ValueError: bad shape; OSError: refused"


def test_a_nested_group_is_flattened_rather_than_named():
    inner = BaseExceptionGroup("inner", [ValueError("bad shape")])
    outer = BaseExceptionGroup("outer", [inner])

    assert _describe(outer) == "ValueError: bad shape"


def test_a_plain_exception_is_described_as_itself():
    assert _describe(RuntimeError("boom")) == "RuntimeError: boom"
